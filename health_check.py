"""
health_check.py
---------------
Core CSV validation and repair logic.
No Azure dependencies — pure Python, fully testable in isolation.

Handles pipe-delimited CSVs where:
- Valid lines end with CRLF  (\r\n)
- Broken lines have an embedded bare LF (\n) inside a field value,
  causing one logical record to split across two (or more) physical lines.
- Some lines have a split CRLF: the \r ended up on the next physical line
  as a lone \r (stray CR), caused by the source emitting a bare \n instead
  of \r\n for that row.

The visible symptom: line N+1 starts with |, making ITEM_NUMBER appear blank.
"""

import logging
from dataclasses import dataclass, field
from typing import Optional

DELIMITER      = b"|"
LF             = b"\n"
CRLF           = b"\r\n"


# ─── Result types ─────────────────────────────────────────────────────────────

@dataclass
class RepairEntry:
    line_number:    int
    column_name:    str
    rule_violated:  str          # EMBEDDED_BARE_LF | BLANK_ITEM_NUMBER | UNESCAPED_QUOTE | STRAY_CR
    original_value: str
    repaired_value: str
    repair_action:  str


@dataclass
class HealthCheckResult:
    status:           str        # VALIDATED | REPAIRED | QUARANTINED
    clean_bytes:      Optional[bytes] = None
    logical_rows_in:  int = 0
    logical_rows_out: int = 0
    repairs:          list = field(default_factory=list)
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

    Detection
    ---------
    Split the raw file on bare LF.  Every healthy line ends with \\r after
    the split (it was \\r\\n).  A line with an embedded bare LF will have:
      - no trailing \\r, AND
      - fewer pipes than the expected column count.

    A stray-CR line (sole \\r on its own physical line) is the artefact of
    a source row that ended with a bare \\n instead of \\r\\n — the \\r
    belonging to that row landed on the next split segment.  These carry
    no data and are skipped with a REPAIRED log entry.
    NOTE: logical_rows_in is NOT incremented here — it was already counted
    when the preceding bare-LF row was joined, so counts_match stays True.

    Repair
    ------
    Concatenate the broken line with the following physical line(s) until
    the pipe count reaches the expected value.  The join is recorded in
    the repair log so there is a full audit trail.

    Reconciliation
    --------------
    logical_rows_in  == logical data records parsed from raw bytes.
    logical_rows_out == logical data records in the clean output.
    For LF-join repairs and stray-CR removals these are always equal.
    A mismatch means something went wrong and the caller should quarantine.
    """

    # ── Guard: empty file ─────────────────────────────────────────────────────
    if not raw_bytes:
        return HealthCheckResult(
            status="QUARANTINED",
            quarantine_reason="File is zero bytes"
        )

    physical        = raw_bytes.split(LF)
    header          = physical[0]
    expected_pipes  = header.rstrip(b"\r").count(DELIMITER)

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

        # ── Stray-CR line: bare \r with no data ───────────────────────────────
        # Artefact of a source row that ended with \n instead of \r\n.
        # The \r was split onto its own physical segment — it carries no data.
        # We drop it and log the repair.
        # logical_rows_in is NOT incremented here: the preceding bare-LF row
        # already incremented it during its join, so counts_match stays True.
        if line == b"\r":
            repairs.append(RepairEntry(
                line_number    = i + 1,
                column_name    = "N/A",
                rule_violated  = "STRAY_CR",
                original_value = repr(line),
                repaired_value = "(line removed)",
                repair_action  = "REMOVED_STRAY_CR",
            ))
            logging.warning(
                f"[HealthCheck] {file_name} | "
                f"Line {i + 1}: stray CR removed "
                f"(source emitted bare LF on previous row)"
            )
            i += 1
            continue

        pipes = line.count(DELIMITER)

        # ── Healthy line: correct pipe count + trailing \r ────────────────────
        if pipes == expected_pipes and line.endswith(b"\r"):
            logical_in += 1
            _flag_blank_item_number(line, i + 1, repairs)
            logical_rows.append(line)
            i += 1
            continue

        # ── Broken line: bare-LF split ────────────────────────────────────────
        if pipes < expected_pipes and not line.endswith(b"\r"):
            origin   = i + 1       # 1-based for logging
            joined   = line
            consumed = 1

            while joined.count(DELIMITER) < expected_pipes:
                nxt = i + consumed
                if nxt >= len(physical):
                    break
                # Skip any stray-CR segment that appears mid-join
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
                    f"Repaired line {origin}: embedded LF in ITEM_DESCRIPTION — "
                    f"joined {consumed} physical lines"
                )
                logical_in += 1
                # Check for blank ITEM_NUMBER on the fully joined row
                _flag_blank_item_number(joined, origin, repairs)
                logical_rows.append(joined)
                i += consumed

            else:
                return HealthCheckResult(
                    status="QUARANTINED",
                    quarantine_reason=(
                        f"Line {origin}: embedded LF detected but cannot "
                        f"reconstruct a complete row after joining {consumed} lines "
                        f"(found {joined.count(DELIMITER)} pipes, "
                        f"expected {expected_pipes})"
                    )
                )
            continue

        # ── Bad pipe count on a CRLF line — cannot auto-repair ────────────────
        if pipes != expected_pipes and line.endswith(b"\r"):
            return HealthCheckResult(
                status="QUARANTINED",
                quarantine_reason=(
                    f"Line {i + 1}: wrong column count. "
                    f"Expected {expected_pipes + 1} columns, "
                    f"got {pipes + 1}. Cannot auto-repair."
                )
            )

        # ── Unhandled case: excess pipes, no trailing \r — quarantine ─────────
        # Reached if pipes > expected_pipes and line does not end with \r.
        # Cannot determine intent; quarantine rather than silently pass through.
        return HealthCheckResult(
            status="QUARANTINED",
            quarantine_reason=(
                f"Line {i + 1}: unexpected format — "
                f"{pipes} pipes found (expected {expected_pipes}), "
                f"no trailing CR. Cannot auto-repair."
            )
        )

    # ── Reassemble with normalised CRLF endings ───────────────────────────────
    clean_bytes  = b"".join(r.rstrip(b"\r") + CRLF for r in logical_rows)
    logical_out  = len(logical_rows) - 1      # subtract header row

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

    The bad pattern:  "This is a "text"."
    The fix:          "This is a ""text"."
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
            c = line[i]

            if c == '"':
                next_ch = line[i + 1] if i + 1 < n else ""

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
    """Log a warning entry when ITEM_NUMBER (field 0) is blank."""
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
