import io
import os
import json
import logging
import urllib.request
from datetime import datetime
import azure.functions as func
from azure.storage.blob import BlobServiceClient, ContentSettings

from health_check import validate_and_repair, detect_and_repair_unescaped_quotes, RepairEntry, HealthCheckResult

app = func.FunctionApp()


def send_teams_alert(actual_count: int, expected: int = 46):
    """Post an alert card to a Teams chat via Power Automate Workflows webhook.
    Never raises — Teams failure must not block the pipeline.
    """
    try:
        webhook_url = os.environ["TEAMS_WEBHOOK_URL"]
        run_date    = datetime.utcnow().strftime("%Y-%m-%d")
        missing     = expected - actual_count

        payload = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "contentUrl": None,
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.2",
                        "body": [
                            {
                                "type": "TextBlock",
                                "text": "⚠️ OPH File Count Alert",
                                "weight": "Bolder",
                                "size": "Large",
                                "color": "Warning",
                                "wrap": True
                            },
                            {
                                "type": "FactSet",
                                "facts": [
                                    {"title": "Date",           "value": run_date},
                                    {"title": "Expected Files", "value": str(expected)},
                                    {"title": "Received Files", "value": str(actual_count)},
                                    {"title": "Missing Files",  "value": str(missing)}
                                ]
                            },
                            {
                                "type": "TextBlock",
                                "text": (
                                    f"The pipeline has continued and will load the "
                                    f"{actual_count} file(s) received. "
                                    f"Please check the SFTP inbound folder: "
                                    f"bi-sftp-production → BI → oph-extracts → inbound"
                                ),
                                "wrap": True,
                                "color": "Attention"
                            }
                        ]
                    }
                }
            ]
        }

        data = json.dumps(payload).encode("utf-8")
        req  = urllib.request.Request(
            webhook_url,
            data=data,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            response_body = resp.read().decode("utf-8")
            logging.info(
                f"[HealthCheck] Teams alert sent — "
                f"actual={actual_count} expected={expected} "
                f"| HTTP {resp.status} | response={response_body}"
            )

    except Exception as e:
        logging.error(
            f"[HealthCheck] Teams alert FAILED (pipeline continues) — {str(e)}"
        )


def _repaired_filename(file_name: str) -> str:
    """Return the blob name for a repaired file.

    Examples
    --------
    file2.csv        → file2_repaired.csv
    archive.tar.csv  → archive.tar_repaired.csv
    """
    base, ext = os.path.splitext(file_name)
    return f"{base}_repaired{ext}"


def _upload_run_log(
    blob_svc: BlobServiceClient,
    container: str,
    quarantine_path: str,
    run_ts: str,
    log_lines: list[str],
) -> None:
    """Write a plain-text run log to the quarantine folder.

    The blob name is:  <quarantine_path>/run_logs/run_<YYYYMMDD_HHMMSS_UTC>.txt

    Never raises — log failure must not block the pipeline.
    """
    try:
        log_blob_name = f"{quarantine_path}/run_logs/run_{run_ts}.txt"
        log_content   = "\n".join(log_lines).encode("utf-8")

        blob_svc.get_blob_client(
            container=container, blob=log_blob_name
        ).upload_blob(
            log_content,
            overwrite=True,
            content_settings=ContentSettings(content_type="text/plain"),
        )
        logging.info(
            f"[HealthCheck] Run log written → {container}/{log_blob_name}"
        )
    except Exception as e:
        logging.error(
            f"[HealthCheck] Run log upload FAILED (pipeline continues) — {str(e)}"
        )


def _normalise_filenames(raw: list) -> list[str]:
    """
    Normalise the filenames list that arrives from ADF.

    ADF Copy Data activity can send filenames in two shapes:

      Shape A — plain strings (Postman / manual calls):
        ["file1.csv", "file2.csv"]

      Shape B — file-object dicts (ADF output.files array):
        [
          {"source": "oph-extracts/inbound/file1.csv",
           "destination": "varun/input/file1.csv"},
          ...
        ]

    In both cases we want only the bare filename (no path prefix).
    For Shape B we prefer the destination path so it matches what
    was actually written to ADLS.
    """
    normalised = []
    for item in raw:
        if isinstance(item, str):
            # Shape A — already a string; strip any leading path
            normalised.append(os.path.basename(item))

        elif isinstance(item, dict):
            # Shape B — ADF GetMetadata childItems:  {"name": "file.csv", "type": "File"}
            # Shape C — ADF Copy output.files:        {"source": "...", "destination": "..."}
            path = (
                item.get("name")                              # GetMetadata childItems
                or item.get("destination")                    # Copy output.files destination
                or item.get("source")                         # Copy output.files source
                or ""
            )
            normalised.append(os.path.basename(path))

        else:
            # Unexpected type — convert to string and log; don't crash
            logging.warning(
                f"[HealthCheck] Unexpected filename entry type "
                f"{type(item).__name__}: {item!r} — skipping"
            )

    return [f for f in normalised if f]   # drop empty strings


@app.function_name(name="health_check_http")
@app.route(route="copyfile", methods=["POST"])
def health_check_http(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("[HealthCheck] HTTP trigger fired")

    # Capture run timestamp once — used for both logging and the log filename
    run_ts      = datetime.utcnow().strftime("%Y%m%d_%H%M%S_UTC")
    run_ts_disp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    try:
        req_body = req.get_json()
        logging.info(f"[HealthCheck] Request body: {req_body}")
    except ValueError:
        return func.HttpResponse("Invalid JSON body", status_code=400)

    # -------------------------------------------------------------------------
    # Accept filenames in two formats:
    #   1. Plain string array  — {"filenames": ["file1.csv", ...]}
    #   2. ADF file-object array — {"filenames": [{"source":..., "destination":...}, ...]}
    # _normalise_filenames() converts both to a flat list of bare filenames.
    # -------------------------------------------------------------------------
    raw_filenames = req_body.get("filenames")

    if not raw_filenames or not isinstance(raw_filenames, list):
        return func.HttpResponse(
            "Missing 'filenames' array in request body", status_code=400
        )

    filenames = _normalise_filenames(raw_filenames)

    if not filenames:
        return func.HttpResponse(
            "No valid filenames could be extracted from 'filenames' array",
            status_code=400
        )

    logging.info(
        f"[HealthCheck] Normalised {len(filenames)} filename(s) from "
        f"{len(raw_filenames)} raw entr(ies)"
    )

    conn_str        = os.environ["ADLS_CONNECTION_STRING"]
    container       = os.environ.get("ADLS_CONTAINER",        "dev")
    input_path      = os.environ.get("ADLS_INPUT_PATH",       "varun/input")
    staged_path     = os.environ.get("ADLS_STAGED_PATH",      "varun/output/staged")
    quarantine_path = os.environ.get("ADLS_QUARANTINE_PATH",  "varun/output/quarantine")

    blob_svc = BlobServiceClient.from_connection_string(conn_str)
    results  = []

    # -------------------------------------------------------------------------
    # Run-log buffer
    # -------------------------------------------------------------------------
    log_buf: list[str] = [
        "=" * 72,
        f"OPH Health-Check Pipeline Run Log",
        f"Run timestamp : {run_ts_disp}",
        f"Files received: {len(filenames)}",
        "=" * 72,
        "",
    ]

    for file_name in filenames:
        log_buf.append(f"--- {file_name} ---")

        if not file_name.endswith(".csv"):
            msg = f"SKIPPED — not a CSV: {file_name}"
            results.append(msg)
            log_buf.append(f"  Status : SKIPPED (not a CSV)")
            log_buf.append("")
            continue

        try:
            # Read source blob
            input_blob = blob_svc.get_blob_client(
                container=container,
                blob=f"{input_path}/{file_name}"
            )
            raw_bytes = input_blob.download_blob().readall()
            log_buf.append(f"  Size   : {len(raw_bytes)} bytes")
            logging.info(
                f"[HealthCheck] FILE READ — {file_name} | size={len(raw_bytes)} bytes"
            )

            # ------------------------------------------------------------------
            # Validate and repair (existing structural checks)
            # ------------------------------------------------------------------
            result: HealthCheckResult = validate_and_repair(raw_bytes, file_name)
            logging.info(
                f"[HealthCheck] Validation result — {file_name} "
                f"| status={result.status} "
                f"| rows_in={result.logical_rows_in} "
                f"| rows_out={result.logical_rows_out}"
            )

            # ------------------------------------------------------------------
            # Unescaped-quote validation
            # ------------------------------------------------------------------
            if result.status == "QUARANTINED" or result.clean_bytes is None:
                quote_repair_count = 0
                quote_issues       = []
                logging.info(
                    f"[HealthCheck] Quote check SKIPPED — "
                    f"{file_name} is already QUARANTINED"
                )
            else:
                repaired_bytes, quote_repair_count, quote_issues = \
                    detect_and_repair_unescaped_quotes(result.clean_bytes, file_name)

                if quote_repair_count > 0:
                    logging.warning(
                        f"[HealthCheck] UNESCAPED QUOTES — {file_name} | "
                        f"{quote_repair_count} line(s) repaired"
                    )
                    for issue in quote_issues:
                        logging.warning(f"[HealthCheck]   {issue}")

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

                    if result.status != "QUARANTINED":
                        result.status = "REPAIRED"
                else:
                    logging.info(
                        f"[HealthCheck] Quote check OK — no unescaped quotes in {file_name}"
                    )

            # ------------------------------------------------------------------
            # Routing
            # ------------------------------------------------------------------
            if result.status == "QUARANTINED" or not result.counts_match:
                dest        = f"{quarantine_path}/{file_name}"
                data        = raw_bytes
                status_tag  = "QUARANTINED"
                dest_label  = f"{container}/{dest}"

            elif result.status == "REPAIRED":
                repaired_name = _repaired_filename(file_name)
                dest          = f"{staged_path}/{repaired_name}"
                data          = result.clean_bytes
                status_tag    = "REPAIRED"
                dest_label    = f"{container}/{dest}"

            else:  # VALID
                dest        = f"{staged_path}/{file_name}"
                data        = result.clean_bytes
                status_tag  = "VALID"
                dest_label  = f"{container}/{dest}"

            # Upload
            blob_svc.get_blob_client(
                container=container, blob=dest
            ).upload_blob(
                data,
                overwrite=True,
                content_settings=ContentSettings(content_type="text/csv"),
            )
            logging.info(
                f"[HealthCheck] SUCCESS — {file_name} → {dest_label}"
            )

            quote_note = (
                f" | quote_repairs={quote_repair_count}" if quote_repair_count > 0 else ""
            )
            result_line = (
                f"{status_tag} — {file_name} → {dest_label} "
                f"| rows={result.logical_rows_out} "
                f"| repairs={result.repairs_made}"
                f"{quote_note}"
            )
            results.append(result_line)

            log_buf.append(f"  Status       : {status_tag}")
            log_buf.append(f"  Destination  : {dest_label}")
            log_buf.append(f"  Rows in      : {result.logical_rows_in}")
            log_buf.append(f"  Rows out     : {result.logical_rows_out}")
            log_buf.append(f"  Repairs made : {result.repairs_made}")
            if quote_repair_count > 0:
                log_buf.append(f"  Quote repairs: {quote_repair_count}")
                for issue in quote_issues:
                    log_buf.append(f"    - {issue}")

        except Exception as e:
            err_msg = f"FAILED — {file_name} | error: {str(e)}"
            logging.error(f"[HealthCheck] {err_msg}")
            results.append(err_msg)
            log_buf.append(f"  Status : FAILED")
            log_buf.append(f"  Error  : {str(e)}")

        log_buf.append("")

    # -------------------------------------------------------------------------
    # File count validation
    # -------------------------------------------------------------------------
    expected_count = int(os.environ.get("EXPECTED_FILE_COUNT", "46"))
    csv_files      = [f for f in filenames if f.endswith(".csv")]
    actual_count   = len(csv_files)

    logging.info(
        f"[HealthCheck] File count check — "
        f"actual={actual_count} expected={expected_count}"
    )

    log_buf.append("=" * 72)
    log_buf.append("File Count Check")
    log_buf.append(f"  Expected : {expected_count}")
    log_buf.append(f"  Received : {actual_count}")

    if actual_count < expected_count:
        alert_msg = (
            f"⚠️ TEAMS ALERT SENT — only {actual_count}/{expected_count} "
            f"CSV files received."
        )
        logging.warning(
            f"[HealthCheck] LOW FILE COUNT — "
            f"{actual_count}/{expected_count} files. Sending Teams alert."
        )
        send_teams_alert(actual_count, expected_count)
        results.append(alert_msg)
        log_buf.append(f"  Outcome  : LOW — Teams alert sent")
    else:
        ok_msg = f"✅ FILE COUNT OK — {actual_count}/{expected_count}"
        logging.info(f"[HealthCheck] File count OK — {actual_count}/{expected_count}")
        results.append(ok_msg)
        log_buf.append(f"  Outcome  : OK")

    log_buf.append("=" * 72)
    log_buf.append(f"End of run log — {run_ts_disp}")

    _upload_run_log(blob_svc, container, quarantine_path, run_ts, log_buf)

    return func.HttpResponse("\n".join(results), status_code=200)
