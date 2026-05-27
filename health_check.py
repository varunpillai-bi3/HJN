"""
health_check.py
---------------
Core CSV validation and repair logic.
No Azure dependencies — pure Python, fully testable in isolation.

Handles pipe-delimited CSVs where:
- Valid lines end with CRLF  (\r\n)
- Broken lines have an embedded bare LF (\n) inside a field value,
  causing one logical record to split across two (or more) physical lines.

The visible symptom: line N+1 starts with |, making ITEM_NUMBER appear blank.
"""

import re
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
    rule_violated:  str          # EMBEDDED_BARE_LF | BLANK_ITEM_NUMBER | UNESCAPED_QUOTE
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

    Repair
    ------
    Concatenate the broken line with the following physical line(s) until
    the pipe count reaches the expected value.  The join is recorded in
    the repair log so there is a full audit trail.

    Reconciliation
    --------------
    logical_rows_in  == logical data records parsed from raw bytes.
    logical_rows_out == logical data records in the clean output.
    For LF-join repairs these are always equal (no records dropped).
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
            origin  = i + 1       # 1-based for logging
            joined  = line
            consumed = 1

            while joined.count(DELIMITER) < expected_pipes:
                nxt = i + consumed
                if nxt >= len(physical):
                    break
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

        logical_rows.append(line)
        i += 1

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


# ─── Unescaped quote validation (new) ─────────────────────────────────────────

def detect_and_repair_unescaped_quotes(
    raw_bytes: bytes, file_name: str = ""
) -> tuple:
    """
    Detects and repairs unescaped double-quotes inside quoted fields.

    The bad pattern:  "This is a "text"."
    The fix:          "This is a ""text"."

    A quote inside a quoted field is only valid if it is immediately followed
    by another quote (escaped) or immediately followed by a pipe, newline,
    carriage return, or end-of-string (closing the field). Any other quote
    inside a quoted field is unescaped and must be doubled.

    Works with pipe-delimited (|) files, matching the existing delimiter.

    Returns:
        (repaired_bytes, repair_count, issue_descriptions)
        - repaired_bytes  : bytes with unescaped quotes fixed
        - repair_count    : number of lines that were repaired
        - issue_descriptions : list of human-readable strings per repaired line
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
    """
    Walk the line character by character and fix unescaped quotes inside
    quoted fields. Handles pipe as delimiter (|), escaped quotes (doubled),
    and trailing newlines/carriage returns.
    """
    result = []
    i      = 0
    n      = len(line)

    while i < n:
        ch = line[i]

        # ── Outside a quoted field ────────────────────────────────────────────
        if ch != '"':
            result.append(ch)
            i += 1
            continue

        # ── Opening quote of a field ──────────────────────────────────────────
        result.append('"')
        i += 1

        while i < n:
            c = line[i]

            if c == '"':
                next_ch = line[i + 1] if i + 1 < n else ""

                if next_ch == '"':
                    # Already a valid escaped quote — keep both
                    result.append('""')
                    i += 2

                elif next_ch in ("|", "\n", "\r", ""):
                    # Legitimate closing quote (pipe is the delimiter here)
                    result.append('"')
                    i += 1
                    break

                else:
                    # Unescaped quote mid-field — double it to escape
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






















