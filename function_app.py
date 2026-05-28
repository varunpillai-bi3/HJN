import os
import json
import logging
import urllib.request
from datetime import datetime
import azure.functions as func
from azure.storage.blob import BlobServiceClient, ContentSettings

from health_check import (
    validate_and_repair,
    detect_and_repair_unescaped_quotes,
    RepairEntry,
    HealthCheckResult,
)

app = func.FunctionApp()


# ─── Teams alert ──────────────────────────────────────────────────────────────

def send_teams_alert(
    run_ts_disp:       str,
    actual_count:      int,
    expected:          int,
    quarantined_files: list[dict],   # [{"name": "file.csv", "reason": "..."}]
    repaired_count:    int,
    valid_count:       int,
    log_path:          str,
) -> None:
    """
    Post an Adaptive Card to Teams via Power Automate webhook.

    Card layout
    -----------
    Status   : ✅ Good  |  🚨 Action Needed
    ─────────────────────────────────────────
    Run Time          : ...
    Total Files       : ...
    Valid Files       : ...
    Repaired Files    : ...   (auto-fixed, staged with _repaired suffix)
    Quarantined Files : ...
    Run Log           : ...
    ─────────────────────────────────────────
    Quarantined File Details   (only if any)
      • filename — reason

    Never raises — Teams failure must not block the pipeline.
    """
    try:
        webhook_url = os.environ["TEAMS_WEBHOOK_URL"]
        missing     = max(0, expected - actual_count)
        n_quarant   = len(quarantined_files)

        # ── Status header ─────────────────────────────────────────────────────
        if n_quarant > 0 or missing > 0:
            status_text  = "🚨 Action Needed"
            status_color = "Attention"
        else:
            status_text  = "✅ Good"
            status_color = "Good"

        # ── Summary facts ─────────────────────────────────────────────────────
        summary_facts = [
            {"title": "Status",            "value": status_text},
            {"title": "Run Time",          "value": run_ts_disp},
            {"title": "Total Files",       "value": str(actual_count)},
            {"title": "Valid Files",       "value": str(valid_count)},
            {"title": "Repaired Files",    "value": str(repaired_count)},
            {"title": "Quarantined Files", "value": str(n_quarant)},
            {"title": "Run Log",           "value": log_path},
        ]
        if missing > 0:
            summary_facts.insert(3, {"title": "Missing Files", "value": str(missing)})

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

        # Quarantined file details — name + exact reason
        if quarantined_files:
            body.append({
                "type":    "TextBlock",
                "text":    "**Quarantined File Details**",
                "weight":  "Bolder",
                "color":   "Attention",
                "wrap":    True,
                "spacing": "Medium",
            })
            for qf in quarantined_files:
                body.append({
                    "type":    "TextBlock",
                    "text":    f"• **{qf['name']}**\n  {qf['reason']}",
                    "wrap":    True,
                    "spacing": "Small",
                    "color":   "Attention",
                })

        # Missing files SFTP note
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
    Write a plain-text run log to  <log_path>/YYYY/MM/DD/run_<timestamp>.txt

    Uses ADLS_LOG_PATH (varun/logs) — a folder that is intentionally excluded
    from ADF delete activities so logs accumulate permanently.

    Structure on ADLS:
        varun/logs/
            2026/
                05/
                    27/
                        run_20260527_093012_UTC.txt
                        run_20260527_141500_UTC.txt

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

def _repaired_filename(file_name: str) -> str:
    """file2.csv → file2_repaired.csv"""
    base, ext = os.path.splitext(file_name)
    return f"{base}_repaired{ext}"


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

    # ── Environment variables — all driven from Azure App Settings ────────────
    conn_str        = os.environ["ADLS_CONNECTION_STRING"]
    container       = os.environ.get("ADLS_CONTAINER",       "dev")
    input_path      = os.environ.get("ADLS_INPUT_PATH",      "varun/input")
    staged_path     = os.environ.get("ADLS_STAGED_PATH",     "varun/output/staged")
    quarantine_path = os.environ.get("ADLS_QUARANTINE_PATH", "varun/output/quarantine")
    log_path        = os.environ.get("ADLS_LOG_PATH",        "varun/logs")

    blob_svc = BlobServiceClient.from_connection_string(conn_str)
    results  = []

    # ── Per-run tracking (fed into Teams card) ────────────────────────────────
    quarantined_files: list[dict] = []   # {"name": ..., "reason": ...}
    repaired_files:    list[str]  = []
    valid_files:       list[str]  = []

    # ── Run log buffer ────────────────────────────────────────────────────────
    log_buf: list[str] = [
        "=" * 72,
        "OPH Health-Check Pipeline Run Log",
        f"Run timestamp : {run_ts_disp}",
        f"Files received: {len(filenames)}",
        f"Log path      : {container}/{log_path}",
        "=" * 72,
        "",
    ]

    # ── Process each file ─────────────────────────────────────────────────────
    for file_name in filenames:
        quote_repair_count  = 0
        quote_issues:  list[str] = []
        quarantine_reason: str   = ""

        log_buf.append(f"--- {file_name} ---")

        if not file_name.endswith(".csv"):
            results.append(f"SKIPPED — not a CSV: {file_name}")
            log_buf.append("  Status : SKIPPED (not a CSV)")
            log_buf.append("")
            continue

        try:
            # Read source blob
            raw_bytes = blob_svc.get_blob_client(
                container = container,
                blob      = f"{input_path}/{file_name}",
            ).download_blob().readall()

            log_buf.append(f"  Size   : {len(raw_bytes)} bytes")
            logging.info(
                f"[HealthCheck] FILE READ — {file_name} | size={len(raw_bytes)} bytes"
            )

            # Stage 1 — structural validation + repair
            result: HealthCheckResult = validate_and_repair(raw_bytes, file_name)
            logging.info(
                f"[HealthCheck] Structural check — {file_name} "
                f"| status={result.status} "
                f"| rows_in={result.logical_rows_in} "
                f"| rows_out={result.logical_rows_out}"
            )

            # Stage 2 — unescaped quote repair (skip if already quarantined)
            if result.status != "QUARANTINED" and result.clean_bytes is not None:
                repaired_bytes, quote_repair_count, quote_issues = \
                    detect_and_repair_unescaped_quotes(result.clean_bytes, file_name)

                if quote_repair_count > 0:
                    logging.warning(
                        f"[HealthCheck] UNESCAPED QUOTES — {file_name} | "
                        f"{quote_repair_count} line(s) repaired"
                    )
                    result.clean_bytes = repaired_bytes
                    for issue in quote_issues:
                        result.repairs.append(RepairEntry(
                            line_number    = 0,
                            column_name    = "DESCRIPTION",
                            rule_violated  = "UNESCAPED_QUOTE",
                            original_value = issue,
                            repaired_value = "(unescaped quote doubled)",
                            repair_action  = "DOUBLED_UNESCAPED_QUOTE",
                        ))
                    result.status = "REPAIRED"
                else:
                    logging.info(f"[HealthCheck] Quote check OK — {file_name}")
            else:
                logging.info(
                    f"[HealthCheck] Quote check SKIPPED — {file_name} already QUARANTINED"
                )

            # Capture quarantine reason before routing
            if result.status == "QUARANTINED" or not result.counts_match:
                quarantine_reason = (
                    result.quarantine_reason
                    or (
                        f"Row count mismatch — "
                        f"rows_in={result.logical_rows_in}, "
                        f"rows_out={result.logical_rows_out}"
                    )
                )

            # Route to staged / quarantine
            if result.status == "QUARANTINED" or not result.counts_match:
                dest       = f"{quarantine_path}/{file_name}"
                data       = raw_bytes
                status_tag = "QUARANTINED"
                quarantined_files.append({"name": file_name, "reason": quarantine_reason})

            elif result.status == "REPAIRED":
                dest       = f"{staged_path}/{_repaired_filename(file_name)}"
                data       = result.clean_bytes
                status_tag = "REPAIRED"
                repaired_files.append(file_name)

            else:   # VALIDATED
                dest       = f"{staged_path}/{file_name}"
                data       = result.clean_bytes
                status_tag = "VALID"
                valid_files.append(file_name)

            dest_label = f"{container}/{dest}"

            # Upload result blob
            blob_svc.get_blob_client(
                container=container, blob=dest
            ).upload_blob(
                data,
                overwrite        = True,
                content_settings = ContentSettings(content_type="text/csv"),
            )
            logging.info(f"[HealthCheck] SUCCESS — {file_name} → {dest_label}")

            quote_note  = f" | quote_repairs={quote_repair_count}" if quote_repair_count > 0 else ""
            results.append(
                f"{status_tag} — {file_name} → {dest_label} "
                f"| rows={result.logical_rows_out} "
                f"| repairs={result.repairs_made}"
                f"{quote_note}"
            )

            log_buf.append(f"  Status       : {status_tag}")
            log_buf.append(f"  Destination  : {dest_label}")
            log_buf.append(f"  Rows in      : {result.logical_rows_in}")
            log_buf.append(f"  Rows out     : {result.logical_rows_out}")
            log_buf.append(f"  Repairs made : {result.repairs_made}")
            if status_tag == "QUARANTINED":
                log_buf.append(f"  Reason       : {quarantine_reason}")
            if quote_repair_count > 0:
                log_buf.append(f"  Quote repairs: {quote_repair_count}")
                for issue in quote_issues:
                    log_buf.append(f"    - {issue}")

        except Exception as e:
            err_msg = f"FAILED — {file_name} | error: {str(e)}"
            logging.error(f"[HealthCheck] {err_msg}")
            results.append(err_msg)
            quarantined_files.append({"name": file_name, "reason": f"Exception: {str(e)}"})
            log_buf.append(f"  Status : FAILED")
            log_buf.append(f"  Error  : {str(e)}")

        log_buf.append("")

    # ── File count check ──────────────────────────────────────────────────────
    expected_count = int(os.environ.get("EXPECTED_FILE_COUNT", "46"))
    actual_count   = len([f for f in filenames if f.endswith(".csv")])

    logging.info(
        f"[HealthCheck] File count — actual={actual_count} expected={expected_count}"
    )

    log_buf.append("=" * 72)
    log_buf.append("File Count Check")
    log_buf.append(f"  Expected : {expected_count}")
    log_buf.append(f"  Received : {actual_count}")
    log_buf.append(f"  Valid    : {len(valid_files)}")
    log_buf.append(f"  Repaired : {len(repaired_files)}")
    log_buf.append(f"  Quarant. : {len(quarantined_files)}")

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

    # ── Write log to varun/logs/YYYY/MM/DD/ ───────────────────────────────────
    log_full_path = _upload_run_log(
        blob_svc  = blob_svc,
        container = container,
        log_path  = log_path,
        run_ts    = run_ts,
        log_lines = log_buf,
    )

    # ── Send Teams alert (every run) ──────────────────────────────────────────
    send_teams_alert(
        run_ts_disp       = run_ts_disp,
        actual_count      = actual_count,
        expected          = expected_count,
        quarantined_files = quarantined_files,
        repaired_count    = len(repaired_files),
        valid_count       = len(valid_files),
        log_path          = log_full_path,
    )

    return func.HttpResponse("\n".join(results), status_code=200)
