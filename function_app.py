import os
import re
import json
import logging
import urllib.request
from datetime import datetime
import azure.functions as func
from azure.storage.blob import BlobServiceClient, ContentSettings
from azure.identity import ManagedIdentityCredential
from azure.keyvault.secrets import SecretClient

from health_check import (
    validate_and_repair,
    detect_and_repair_unescaped_quotes,
    HealthCheckResult,
)

app = func.FunctionApp()


# ─── Key Vault helper ──────────────────────────────────────────────────────────

def _get_secret(secret_name: str) -> str:
    """
    Fetch a secret from Azure Key Vault using Managed Identity.
    KEY_VAULT_URL must be set in App Settings (non-secret).
    e.g. https://kvhjaaz1dadp01.vault.azure.net/
    """
    kv_url     = os.environ["KEY_VAULT_URL"]
    credential = ManagedIdentityCredential()
    client     = SecretClient(vault_url=kv_url, credential=credential)
    return client.get_secret(secret_name).value


# ─── Issue classifier ──────────────────────────────────────────────────────────

def _classify_issues(result: HealthCheckResult, quote_repair_count: int) -> list[str]:
    """
    Return a list of human-readable issue descriptions found in a file.
    Called even when we are NOT repairing — purely for notification.
    """
    issues = []

    if result.status == "QUARANTINED":
        reason = result.quarantine_reason or "Unknown quarantine reason"

        if "BLANK_ROW_DETECTED" in reason:
            # Extract line number if present
            m = re.search(r"Line (\d+)", reason)
            line_ref = f" at line {m.group(1)}" if m else ""
            issues.append(f"Blank row detected{line_ref} — ERP export defect (inverted \\n\\r line ending)")

        elif "embedded lf" in reason.lower() or "embedded bare lf" in reason.lower():
            m = re.search(r"Line (\d+)", reason)
            line_ref = f" at line {m.group(1)}" if m else ""
            issues.append(f"Embedded line break in field{line_ref} — record split across multiple physical lines")

        elif "wrong column count" in reason.lower():
            m = re.search(r"Line (\d+)", reason)
            line_ref = f" at line {m.group(1)}" if m else ""
            issues.append(f"Wrong column count{line_ref} — column mismatch, cannot parse row")

        elif "zero bytes" in reason.lower():
            issues.append("File is empty (zero bytes)")

        elif "delimiter" in reason.lower():
            issues.append("Header missing pipe delimiter '|' — file may be in wrong format")

        else:
            issues.append(reason)

    else:
        # VALIDATED or REPAIRED — check what repairs were found
        rule_map = {
            "EMBEDDED_BARE_LF": "Embedded line break in field — record split across multiple physical lines",
            "STRAY_CR":         "Stray carriage return found — artefact of broken line ending",
            "BLANK_ITEM_NUMBER":"Blank Item Number — first field empty after line-break join",
            "UNESCAPED_QUOTE":  "Unescaped double-quote inside field value",
        }
        seen = set()
        for r in result.repairs:
            label = rule_map.get(r.rule_violated, r.rule_violated)
            if label not in seen:
                issues.append(label)
                seen.add(label)

    if quote_repair_count > 0 and "Unescaped double-quote inside field value" not in issues:
        issues.append("Unescaped double-quote inside field value")

    return issues


# ─── Teams alert ──────────────────────────────────────────────────────────────

def send_teams_alert(
    run_ts_disp:    str,
    actual_count:   int,
    expected:       int,
    valid_files:    list[str],
    invalid_files:  list[dict],   # [{"name": "...", "file_no": N, "issues": [...]}]
    log_path:       str,
) -> None:
    """
    Post an Adaptive Card to Teams.

    Card layout
    ───────────
    OPH Data Pipeline — Run Summary
    ─────────────────────────────────────────────────────
    Status          : ✅ All Good  |  🚨 Issues Found
    Run Time        : ...
    Files Received  : ...
    ✅ Valid Files   : ...
    ❌ Invalid Files : ...
    Run Log         : ...

    Invalid Files Detail  (only if any invalid)
    ┌────┬──────────────────┬─────────────────────────────────────────┐
    │ No │ File Name        │ Issues Identified                       │
    ├────┼──────────────────┼─────────────────────────────────────────┤
    │  1 │ file1.csv        │ Blank row detected at line 5210         │
    │  2 │ file2.csv        │ Wrong column count at line 42           │
    └────┴──────────────────┴─────────────────────────────────────────┘

    Never raises — Teams failure must not block the pipeline.
    """
    try:
        webhook_url  = _get_secret("webhook-url-teams-oph")
        n_invalid    = len(invalid_files)
        n_valid      = len(valid_files)
        missing      = max(0, expected - actual_count)

        # ── Status ────────────────────────────────────────────────────────────
        if n_invalid > 0 or missing > 0:
            status_text  = "🚨 Issues Found — Action Needed"
            status_color = "Attention"
        else:
            status_text  = "✅ All Good"
            status_color = "Good"

        # ── Summary facts ─────────────────────────────────────────────────────
        summary_facts = [
            {"title": "Status",           "value": status_text},
            {"title": "Run Time",         "value": run_ts_disp},
            {"title": "Files Received",   "value": str(actual_count)},
            {"title": "✅ Valid Files",    "value": str(n_valid)},
            {"title": "❌ Invalid Files",  "value": str(n_invalid)},
            {"title": "Run Log",          "value": log_path},
        ]
        if missing > 0:
            summary_facts.insert(4, {"title": "⚠️ Missing Files", "value": str(missing)})

        # ── Card body ─────────────────────────────────────────────────────────
        body = [
            {
                "type":   "TextBlock",
                "text":   "OPH Data Pipeline — Run Summary",
                "weight": "Bolder",
                "size":   "Large",
                "wrap":   True,
            },
            {
                "type":  "FactSet",
                "facts": summary_facts,
            },
        ]

        # ── Invalid files detail table ────────────────────────────────────────
        if invalid_files:
            body.append({
                "type":    "TextBlock",
                "text":    "**❌ Invalid Files — Issues Identified**",
                "weight":  "Bolder",
                "color":   "Attention",
                "wrap":    True,
                "spacing": "Medium",
            })

            # Header row
            body.append({
                "type": "ColumnSet",
                "columns": [
                    {"type": "Column", "width": "auto",    "items": [{"type": "TextBlock", "text": "**No**",       "wrap": True, "weight": "Bolder"}]},
                    {"type": "Column", "width": "stretch", "items": [{"type": "TextBlock", "text": "**File Name**","wrap": True, "weight": "Bolder"}]},
                    {"type": "Column", "width": "stretch", "items": [{"type": "TextBlock", "text": "**Issues Identified**", "wrap": True, "weight": "Bolder"}]},
                ],
                "spacing": "Small",
            })

            # Data rows
            for entry in invalid_files:
                issues_text = "\n• ".join(entry["issues"]) if entry["issues"] else "Unknown issue"
                if len(entry["issues"]) > 1:
                    issues_text = "• " + issues_text

                body.append({
                    "type": "ColumnSet",
                    "columns": [
                        {"type": "Column", "width": "auto",    "items": [{"type": "TextBlock", "text": str(entry["file_no"]), "wrap": True, "color": "Attention", "size": "Small"}]},
                        {"type": "Column", "width": "stretch", "items": [{"type": "TextBlock", "text": entry["name"],         "wrap": True, "color": "Attention", "size": "Small"}]},
                        {"type": "Column", "width": "stretch", "items": [{"type": "TextBlock", "text": issues_text,           "wrap": True, "color": "Attention", "size": "Small"}]},
                    ],
                    "spacing": "Small",
                })

        # Missing files note
        if missing > 0:
            body.append({
                "type":    "TextBlock",
                "text":    (
                    f"⚠️ {missing} file(s) missing from expected {expected}. "
                    f"Please check SFTP: bi-sftp-production → BI → oph-extracts → inbound"
                ),
                "wrap":    True,
                "color":   "Warning",
                "spacing": "Medium",
            })

        payload = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "contentUrl":  None,
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type":    "AdaptiveCard",
                        "version": "1.2",
                        "body":    body,
                    },
                }
            ],
        }

        data = json.dumps(payload).encode("utf-8")
        req  = urllib.request.Request(
            webhook_url,
            data    = data,
            headers = {"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            response_body = resp.read().decode("utf-8")
            logging.info(
                f"[HealthCheck] Teams alert sent | HTTP {resp.status} | {response_body}"
            )

    except Exception as e:
        logging.error(
            f"[HealthCheck] Teams alert FAILED (pipeline continues) — {str(e)}"
        )


# ─── Run log upload ────────────────────────────────────────────────────────────

def _upload_run_log(
    blob_svc:   BlobServiceClient,
    container:  str,
    log_path:   str,
    run_ts:     str,
    log_lines:  list[str],
) -> str:
    """
    Write a plain-text run log to <log_path>/YYYY/MM/DD/run_<timestamp>.txt
    Returns the full blob path so it can be shown in the Teams card.
    Never raises — log failure must not block the pipeline.
    """
    _now      = datetime.utcnow()
    year      = _now.strftime("%Y")
    month     = _now.strftime("%m")
    day       = _now.strftime("%d")
    blob_name = f"{log_path}/{year}/{month}/{day}/run_{run_ts}.txt"

    try:
        log_content = "\n".join(log_lines).encode("utf-8")
        blob_svc.get_blob_client(
            container=container,
            blob=blob_name,
        ).upload_blob(
            log_content,
            overwrite        = True,
            content_settings = ContentSettings(content_type="text/plain"),
        )
        logging.info(f"[HealthCheck] Run log written → {container}/{blob_name}")
        return f"{container}/{blob_name}"

    except Exception as e:
        logging.error(
            f"[HealthCheck] Run log upload FAILED (pipeline continues) — {str(e)}"
        )
        return f"{container}/{blob_name} (UPLOAD FAILED)"


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _normalise_filenames(raw: list) -> list[str]:
    """
    Accept filenames from ADF in three shapes and return bare filenames.
      Shape A — plain strings:   ["file1.csv", ...]
      Shape B — Copy output:     [{"source": "...", "destination": "..."}, ...]
      Shape C — GetMetadata:     [{"name": "file.csv", "type": "File"}, ...]
    """
    normalised = []
    for item in raw:
        if isinstance(item, str):
            normalised.append(os.path.basename(item))
        elif isinstance(item, dict):
            path = (
                item.get("name")
                or item.get("destination")
                or item.get("source")
                or ""
            )
            normalised.append(os.path.basename(path))
        else:
            logging.warning(
                f"[HealthCheck] Unexpected filename entry type "
                f"{type(item).__name__}: {item!r} — skipping"
            )
    return [f for f in normalised if f]


# ─── HTTP trigger ──────────────────────────────────────────────────────────────

@app.function_name(name="health_check_http")
@app.route(route="copyfile", methods=["POST"])
def health_check_http(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("[HealthCheck] HTTP trigger fired")

    _now        = datetime.utcnow()
    run_ts      = _now.strftime("%Y%m%d_%H%M%S_UTC")
    run_ts_disp = _now.strftime("%Y-%m-%d %H:%M:%S UTC")

    # ── Parse request ─────────────────────────────────────────────────────────
    try:
        req_body = req.get_json()
        logging.info(f"[HealthCheck] Request body: {req_body}")
    except ValueError:
        return func.HttpResponse("Invalid JSON body", status_code=400)

    raw_filenames = req_body.get("filenames")
    if not raw_filenames or not isinstance(raw_filenames, list):
        return func.HttpResponse(
            "Missing 'filenames' array in request body", status_code=400
        )

    filenames = _normalise_filenames(raw_filenames)
    if not filenames:
        return func.HttpResponse(
            "No valid filenames could be extracted from 'filenames' array",
            status_code=400,
        )

    logging.info(
        f"[HealthCheck] Normalised {len(filenames)} filename(s) "
        f"from {len(raw_filenames)} raw entr(ies)"
    )

    # ── Read secrets from Key Vault ───────────────────────────────────────────
    try:
        conn_str = _get_secret("adls-con-str")
        logging.info("[HealthCheck] ADLS connection string fetched from KV")
    except Exception as e:
        logging.error(f"[HealthCheck] Failed to fetch adls-con-str from KV — {e}")
        return func.HttpResponse(
            f"Failed to fetch secret from Key Vault: {str(e)}", status_code=500
        )

    # ── Read configuration from ADF request body ──────────────────────────────
    container      = req_body.get("adls_container", "dev")
    input_path     = req_body.get("adls_input_path", "varun/input")
    log_path       = req_body.get("adls_log_path", "varun/logs")
    expected_count = int(req_body.get("expected_file_count", 46))

    # ── Validate container name ───────────────────────────────────────────────
    logging.info(f"[HealthCheck] Using container: {container}")
    if "/" in container or not container.strip():
        logging.error(f"[HealthCheck] Invalid container name passed: {container}")
        return func.HttpResponse(
            f"Invalid container name: {container}", status_code=400
        )

    allowed_containers = {"dev"}
    if container not in allowed_containers:
        logging.error(f"[HealthCheck] Unexpected container: {container}")
        return func.HttpResponse(
            f"Unexpected container: {container}", status_code=400
        )

    blob_svc = BlobServiceClient.from_connection_string(conn_str)
    logging.info(f"[HealthCheck] Confirmed container in use: {container}")

    # ── Per-run tracking ──────────────────────────────────────────────────────
    valid_files:   list[str]  = []
    invalid_files: list[dict] = []   # {"file_no": N, "name": "...", "issues": [...]}
    results:       list[str]  = []
    file_no = 0

    # ── Run log buffer ────────────────────────────────────────────────────────
    log_buf: list[str] = [
        "=" * 72,
        "OPH Health-Check Pipeline Run Log  [NOTIFICATION MODE — read-only]",
        f"Run timestamp : {run_ts_disp}",
        f"Files received: {len(filenames)}",
        f"Log path      : {container}/{log_path}",
        "=" * 72,
        "",
    ]

    # ── Inspect each file (read-only — no writes to staged/quarantine) ────────
    for file_name in filenames:
        log_buf.append(f"--- {file_name} ---")

        if not file_name.endswith(".csv"):
            results.append(f"SKIPPED — not a CSV: {file_name}")
            log_buf.append("  Status : SKIPPED (not a CSV)")
            log_buf.append("")
            continue

        file_no += 1

        try:
            # Read source blob — no writes anywhere
            raw_bytes = blob_svc.get_blob_client(
                container = container,
                blob      = f"{input_path}/{file_name}",
            ).download_blob().readall()

            log_buf.append(f"  Size   : {len(raw_bytes)} bytes")
            logging.info(
                f"[HealthCheck] FILE READ — {file_name} | size={len(raw_bytes)} bytes"
            )

            # Stage 1 — structural inspection
            result: HealthCheckResult = validate_and_repair(raw_bytes, file_name)
            logging.info(
                f"[HealthCheck] Structural check — {file_name} "
                f"| status={result.status} "
                f"| rows_in={result.logical_rows_in} "
                f"| rows_out={result.logical_rows_out}"
            )

            # Stage 2 — unescaped quote inspection
            quote_repair_count = 0
            if result.status != "QUARANTINED" and result.clean_bytes is not None:
                _, quote_repair_count, _ = detect_and_repair_unescaped_quotes(
                    result.clean_bytes, file_name
                )
                if quote_repair_count > 0:
                    logging.warning(
                        f"[HealthCheck] UNESCAPED QUOTES FOUND — {file_name} | "
                        f"{quote_repair_count} line(s) affected"
                    )

            # ── Classify as VALID or INVALID ──────────────────────────────────
            is_invalid = (
                result.status == "QUARANTINED"
                or not result.counts_match
                or len(result.repairs) > 0
                or quote_repair_count > 0
            )

            if is_invalid:
                issues = _classify_issues(result, quote_repair_count)
                invalid_files.append({
                    "file_no": file_no,
                    "name":    file_name,
                    "issues":  issues,
                })
                results.append(
                    f"INVALID — {file_name} | issues: {'; '.join(issues)}"
                )
                log_buf.append(f"  Status : INVALID")
                for issue in issues:
                    log_buf.append(f"  Issue  : {issue}")
            else:
                valid_files.append(file_name)
                results.append(f"VALID — {file_name}")
                log_buf.append(f"  Status : VALID")

            log_buf.append(f"  Rows in : {result.logical_rows_in}")
            log_buf.append(f"  Rows out: {result.logical_rows_out}")

        except Exception as e:
            err_msg = f"FAILED — {file_name} | error: {str(e)}"
            logging.error(f"[HealthCheck] {err_msg}")
            results.append(err_msg)
            invalid_files.append({
                "file_no": file_no,
                "name":    file_name,
                "issues":  [f"Read error: {str(e)}"],
            })
            log_buf.append(f"  Status : FAILED")
            log_buf.append(f"  Error  : {str(e)}")

        log_buf.append("")

    # ── File count check ──────────────────────────────────────────────────────
    expected_count = int(os.environ.get("EXPECTED_FILE_COUNT", str(expected_count)))
    actual_count   = len([f for f in filenames if f.endswith(".csv")])

    logging.info(
        f"[HealthCheck] File count — actual={actual_count} expected={expected_count}"
    )

    log_buf.append("=" * 72)
    log_buf.append("File Count Summary")
    log_buf.append(f"  Expected : {expected_count}")
    log_buf.append(f"  Received : {actual_count}")
    log_buf.append(f"  Valid    : {len(valid_files)}")
    log_buf.append(f"  Invalid  : {len(invalid_files)}")

    if actual_count < expected_count:
        missing = expected_count - actual_count
        logging.warning(
            f"[HealthCheck] LOW FILE COUNT — {actual_count}/{expected_count}"
        )
        results.append(
            f"⚠️ LOW FILE COUNT — {actual_count}/{expected_count} CSV files. "
            f"{missing} missing."
        )
        log_buf.append(f"  Outcome  : LOW — {missing} file(s) missing")
    else:
        logging.info(f"[HealthCheck] File count OK — {actual_count}/{expected_count}")
        results.append(f"✅ FILE COUNT OK — {actual_count}/{expected_count}")
        log_buf.append(f"  Outcome  : OK")

    log_buf.append("=" * 72)
    log_buf.append(f"End of run — {run_ts_disp}")

    # ── Write run log ─────────────────────────────────────────────────────────
    log_full_path = _upload_run_log(
        blob_svc  = blob_svc,
        container = container,
        log_path  = log_path,
        run_ts    = run_ts,
        log_lines = log_buf,
    )

    # ── Send Teams alert ──────────────────────────────────────────────────────
    send_teams_alert(
        run_ts_disp   = run_ts_disp,
        actual_count  = actual_count,
        expected      = expected_count,
        valid_files   = valid_files,
        invalid_files = invalid_files,
        log_path      = log_full_path,
    )

    return func.HttpResponse("\n".join(results), status_code=200)
