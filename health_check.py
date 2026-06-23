"""
health_check.py
---------------
Core CSV validation and repair logic.
No Azure dependencies — pure Python, fully testable in isolation.

Handles pipe-delimited CSVs where:
- Valid lines end with CRLF (\r\n)
- Broken lines have an embedded bare LF (\n) inside a field value,
  causing one logical record to split across two or more physical lines.
- Some lines have a blank row caused by an inverted line ending (\n\r)
  from the ERP export — quarantined with a clear reason for ERP team.

The visible symptom of embedded LF: line N+1 starts with |, making
ITEM_NUMBER appear blank.
"""

import logging
from dataclasses import dataclass, field
from typing import Optional

DELIMITER = b"|"
LF        = b"\n"
CRLF      = b"\r\n"


# ─── Result types ─────────────────────────────────────────────────────────────

@dataclass
class RepairEntry:
    line_number:    int
    column_name:    str
    rule_violated:  str   # EMBEDDED_BARE_LF | BLANK_ITEM_NUMBER | UNESCAPED_QUOTE | STRAY_CR
    original_value: str
    repaired_value: str
    repair_action:  str


@dataclass
class HealthCheckResult:
    status:            str        # VALIDATED | REPAIRED | QUARANTINED
    clean_bytes:       Optional[bytes] = None
    logical_rows_in:   int = 0
    logical_rows_out:  int = 0
    repairs:           list = field(default_factory=list)
    quarantine_reason: Optional[str] = None

    @property
    def repairs_made(self) -> int:
        return len(self.repairs)

    @property
    def counts_match(self) -> bool:
        return self.logical_rows_in == self.logical_rows_out


# ─── Main entry point ─────────────────────────────────────────────────────────

def validate_and_repair(raw_bytes: bytes, file_name: str = "") -> HealthCheckResult:
    """
    Validates and repairs a pipe-delimited CSV file.

    Detection / repair cases (in order)
    ------------------------------------
    1. STRAY_CR
       A lone b"\\r" physical segment — artefact of a preceding bare-LF row.
       Dropped silently. logical_in NOT incremented.

    2. Healthy CRLF line
       Correct pipe count + trailing \\r. Accepted as-is.

    3. EMBEDDED_BARE_LF  (pipes < expected, no trailing \\r)
       Field value contains a bare \\n splitting one record across lines.
       Joined until pipe count is satisfied.

    4. Wrong pipe count on CRLF line
       Cannot repair — quarantine.

    5. BLANK_ROW_DETECTED  (pipes == expected, no trailing \\r, next seg == b"\\r")
       ERP export defect: line ending written as \\n\\r instead of \\r\\n.
       The \\r lands alone on the next segment, appearing as a blank row in Excel.
       Policy: DO NOT auto-repair. Quarantine with clear reason for ERP team.

    6. Unhandled
       Cannot determine intent — quarantine.
    """

    if not raw_bytes:
        return HealthCheckResult(
            status="QUARANTINED",
            quarantine_reason="File is zero bytes"
        )

    physical       = raw_bytes.split(LF)
    header         = physical[0]
    expected_pipes = header.rstrip(b"\r").count(DELIMITER)

    if expected_pipes < 1:
        return HealthCheckResult(
            status="QUARANTINED",
            quarantine_reason=(
                f"Header does not contain delimiter '|'. "
                f"Pipes found: {expected_pipes}"
            )
        )

    repairs      = []
    logical_rows = [header]
    logical_in   = 0
    i            = 1

    while i < len(physical):
        line = physical[i]

        # Skip trailing empty line at EOF
        if i == len(physical) - 1 and line.strip(b"\r") == b"":
            i += 1
            continue

        # ── Case 1: Stray-CR segment ──────────────────────────────────────────
        if line == b"\r":
            repairs.append(RepairEntry(
                line_number    = i + 1,
                column_name    = "N/A",
                rule_violated  = "STRAY_CR",
                original_value = repr(line),
                repaired_value = "(segment removed)",
                repair_action  = "REMOVED_STRAY_CR",
            ))
            logging.warning(
                f"[HealthCheck] {file_name} | "
                f"Line {i + 1}: stray CR removed"
            )
            i += 1
            continue

        pipes = line.count(DELIMITER)

        # ── Case 2: Healthy CRLF line ─────────────────────────────────────────
        if pipes == expected_pipes and line.endswith(b"\r"):
            logical_in += 1
            _flag_blank_item_number(line, i + 1, repairs)
            logical_rows.append(line)
            i += 1
            continue

        # ── Case 3: Embedded bare-LF split ───────────────────────────────────
        if pipes < expected_pipes and not line.endswith(b"\r"):
            origin   = i + 1
            joined   = line
            consumed = 1

            while joined.count(DELIMITER) < expected_pipes:
                nxt = i + consumed
                if nxt >= len(physical):
                    break
                if physical[nxt] == b"\r":
                    consumed += 1
                    continue
                joined = joined + physical[nxt]
                consumed += 1

            if joined.count(DELIMITER) == expected_pipes:
                raw_fragment = b"\n".join(physical[i : i + consumed])
                repaired_str = joined.rstrip(b"\r").decode("utf-8", errors="replace")

                repairs.append(RepairEntry(
                    line_number    = origin,
                    column_name    = "ITEM_DESCRIPTION",
                    rule_violated  = "EMBEDDED_BARE_LF",
                    original_value = raw_fragment.decode("utf-8", errors="replace")[:500],
                    repaired_value = repaired_str[:500],
                    repair_action  = f"JOINED_{consumed}_PHYSICAL_LINES",
                ))
                logging.info(
                    f"[HealthCheck] {file_name} | "
                    f"Repaired line {origin}: embedded LF — joined {consumed} lines"
                )
                logical_in += 1
                _flag_blank_item_number(joined, origin, repairs)
                logical_rows.append(joined)
                i += consumed
            else:
                return HealthCheckResult(
                    status="QUARANTINED",
                    quarantine_reason=(
                        f"Line {origin}: embedded LF detected but cannot "
                        f"reconstruct row after joining {consumed} lines "
                        f"(found {joined.count(DELIMITER)} pipes, "
                        f"expected {expected_pipes})"
                    )
                )
            continue

        # ── Case 4: Wrong pipe count on CRLF line ────────────────────────────
        if pipes != expected_pipes and line.endswith(b"\r"):
            return HealthCheckResult(
                status="QUARANTINED",
                quarantine_reason=(
                    f"Line {i + 1}: wrong column count. "
                    f"Expected {expected_pipes + 1} columns, "
                    f"got {pipes + 1}. Cannot auto-repair."
                )
            )

        # ── Case 5: Blank row — ERP export defect (\n\r instead of \r\n) ─────
        if pipes == expected_pipes and not line.endswith(b"\r"):
            origin       = i + 1
            nxt          = i + 1
            blank_line_no = nxt + 1

            if nxt < len(physical) and physical[nxt] == b"\r":
                return HealthCheckResult(
                    status="QUARANTINED",
                    quarantine_reason=(
                        f"BLANK_ROW_DETECTED | "
                        f"Line {blank_line_no}: blank row found. "
                        f"Caused by inverted line ending (\\n\\r instead of \\r\\n) "
                        f"on line {origin}. ERP export defect — "
                        f"file must be regenerated by the ERP team."
                    )
                )

            return HealthCheckResult(
                status="QUARANTINED",
                quarantine_reason=(
                    f"Line {origin}: correct pipe count ({pipes}) "
                    f"but no trailing CR. Cannot auto-repair."
                )
            )

        # ── Case 6: Unhandled ─────────────────────────────────────────────────
        return HealthCheckResult(
            status="QUARANTINED",
            quarantine_reason=(
                f"Line {i + 1}: unexpected format — "
                f"{pipes} pipes (expected {expected_pipes}), "
                f"no trailing CR. Cannot auto-repair."
            )
        )

    # ── Reassemble with normalised CRLF endings ───────────────────────────────
    clean_bytes = b"".join(r.rstrip(b"\r") + CRLF for r in logical_rows)
    logical_out = len(logical_rows) - 1

    status = "REPAIRED" if repairs else "VALIDATED"

    return HealthCheckResult(
        status           = status,
        clean_bytes      = clean_bytes,
        logical_rows_in  = logical_in,
        logical_rows_out = logical_out,
        repairs          = repairs,
    )


# ─── Unescaped quote validation ────────────────────────────────────────────────

def detect_and_repair_unescaped_quotes(
    raw_bytes: bytes, file_name: str = ""
) -> tuple:
    """
    Detects and repairs unescaped double-quotes inside quoted fields.
    Bad pattern:  "This is a "text"."
    Fixed:        "This is a ""text"."
    """
    try:
        text = raw_bytes.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = raw_bytes.decode("latin-1")

    lines        = text.splitlines(keepends=True)
    repaired     = []
    repair_count = 0
    issues       = []

    for line_no, line in enumerate(lines, start=1):
        new_line = _repair_line_quotes(line)
        if new_line != line:
            repair_count += 1
            issues.append(
                f"Line {line_no}: unescaped quote repaired — "
                f"original: {line.rstrip()!r}"
            )
            logging.warning(
                f"[HealthCheck] {file_name} | "
                f"Line {line_no}: unescaped quote repaired"
            )
        repaired.append(new_line)

    repaired_bytes = "".join(repaired).encode("utf-8")
    return repaired_bytes, repair_count, issues


def _repair_line_quotes(line: str) -> str:
    result = []
    i      = 0
    n      = len(line)

    while i < n:
        ch = line[i]
        if ch != '"':
            result.append(ch)
            i += 1
            continue

        result.append('"')
        i += 1

        while i < n:
            c       = line[i]
            next_ch = line[i + 1] if i + 1 < n else ""

            if c == '"':
                if next_ch == '"':
                    result.append('""')
                    i += 2
                elif next_ch in ("|", "\n", "\r", ""):
                    result.append('"')
                    i += 1
                    break
                else:
                    result.append('""')
                    i += 1
            else:
                result.append(c)
                i += 1

    return "".join(result)


# ─── Internal helpers ─────────────────────────────────────────────────────────

def _flag_blank_item_number(line: bytes, line_no: int, repairs: list):
    """Log a warning when ITEM_NUMBER (field 0) is blank."""
    first = line.split(DELIMITER)[0].strip(b"\r")
    if first == b"":
        repairs.append(RepairEntry(
            line_number    = line_no,
            column_name    = "ITEM_NUMBER",
            rule_violated  = "BLANK_ITEM_NUMBER",
            original_value = "",
            repaired_value = "(resolved by LF join — see EMBEDDED_BARE_LF entry)",
            repair_action  = "DETECTED_POST_JOIN",
        ))
