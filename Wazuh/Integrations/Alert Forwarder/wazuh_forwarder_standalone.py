#!/usr/bin/env python3
# ================================================================
# FILE: integrations/wazuh_forwarder_standalone.py
# PURPOSE: Forward Wazuh alerts to AlistoIR without external deps
# NOTES:
# - Uses SQLite for durable state tracking
# - Handles partial JSON lines safely
# - Handles alerts.json rotation / truncation
# - Reads secrets from environment variables
# ================================================================

import json
import os
import random
import ssl
import sqlite3
import sys
import time
import hashlib
import urllib.request
import urllib.error
from datetime import datetime
from typing import Tuple


def env_flag(name: str, default: bool = False) -> bool:
    value = os.getenv(name, "")
    if value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_csv(name: str) -> set[str]:
    value = os.getenv(name, "")
    if not value.strip():
        return set()
    return {item.strip() for item in value.split(",") if item.strip()}


SOAR_URL = os.getenv("TRACKIR_SOAR_URL", "https://<YOUR_ALISTOIR_SERVER_IP_OR_DOMAIN>/alerts/ingest.php").strip()
SOAR_API_KEY = os.getenv("TRACKIR_SOAR_API_KEY", "GLOBAL_API_KEY").strip()
SOAR_TENANT_KEY = os.getenv("TRACKIR_TENANT_KEY", "YOUR_ali_TENANT_KEY").strip()
WAZUH_SOURCE_ID = os.getenv("TRACKIR_WAZUH_SOURCE", "").strip()
WAZUH_ALERTS_FILE = os.getenv("TRACKIR_WAZUH_ALERTS_FILE", "/var/ossec/logs/alerts/alerts.json")
STATE_DB = os.getenv("TRACKIR_STATE_DB", "/var/ossec/integrations/soar_forwarder_state.db")
LOG_FILE = os.getenv("TRACKIR_LOG_FILE", "/var/ossec/logs/integrations/soar_forwarder.log")
MIN_LEVEL = int(os.getenv("TRACKIR_MIN_LEVEL", "3"))
RULE_ID_FILTER = env_csv("TRACKIR_RULE_IDS")
CHECK_INTERVAL = float(os.getenv("TRACKIR_CHECK_INTERVAL", "2"))
REQUEST_TIMEOUT = int(os.getenv("TRACKIR_REQUEST_TIMEOUT", "60"))
MAX_RETRIES = int(os.getenv("TRACKIR_MAX_RETRIES", "5"))
FORWARD_DELAY = float(os.getenv("TRACKIR_FORWARD_DELAY", "0.2"))
PROCESSED_RETENTION_DAYS = int(os.getenv("TRACKIR_PROCESSED_RETENTION_DAYS", "14"))
MAX_ERROR_BODY_LOG = int(os.getenv("TRACKIR_MAX_ERROR_BODY_LOG", "300"))
DISABLE_PROCESSED_STATE = env_flag("TRACKIR_DISABLE_PROCESSED_STATE", False)
DEBUG_ALERTS = env_flag("TRACKIR_DEBUG_ALERTS", False)
START_AT_END_ON_FRESH_RUN = env_flag("TRACKIR_START_AT_END_ON_FRESH_RUN", False)
RESET_CURSOR_ON_START = env_flag("TRACKIR_RESET_CURSOR_ON_START", False)
USER_AGENT = "AlistoIR-Wazuh-Forwarder/1.1"
CA_BUNDLE_CANDIDATES = [
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/cert.pem",
]


def log_message(message: str, level: str = "INFO") -> None:
    """Simple file and console logging."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} - {level} - {message}"
    print(log_entry, flush=True)

    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as handle:
            handle.write(log_entry + "\n")
    except Exception:
        pass


def ensure_parent_dir(path: str) -> None:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def db_connect() -> sqlite3.Connection:
    ensure_parent_dir(STATE_DB)
    connection = sqlite3.connect(STATE_DB)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=NORMAL")
    connection.execute("""
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """)
    connection.execute("""
        CREATE TABLE IF NOT EXISTS processed_alerts (
            alert_id TEXT PRIMARY KEY,
            processed_at INTEGER NOT NULL
        )
    """)
    connection.commit()
    return connection


def db_get_meta(connection: sqlite3.Connection, key: str, default: str = "") -> str:
    row = connection.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row[0] if row else default


def db_set_meta(connection: sqlite3.Connection, key: str, value: str) -> None:
    connection.execute(
        "INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )
    connection.commit()


def db_is_processed(connection: sqlite3.Connection, alert_id: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM processed_alerts WHERE alert_id = ? LIMIT 1",
        (alert_id,),
    ).fetchone()
    return row is not None


def db_mark_processed(connection: sqlite3.Connection, alert_id: str) -> None:
    connection.execute(
        "INSERT OR REPLACE INTO processed_alerts (alert_id, processed_at) VALUES (?, ?)",
        (alert_id, int(time.time())),
    )
    connection.commit()


def db_prune_processed(connection: sqlite3.Connection) -> int:
    cutoff = int(time.time()) - (PROCESSED_RETENTION_DAYS * 86400)
    cursor = connection.execute(
        "DELETE FROM processed_alerts WHERE processed_at < ?",
        (cutoff,),
    )
    connection.commit()
    return cursor.rowcount or 0


def build_ssl_context() -> ssl.SSLContext:
    preferred_bundle = os.getenv("TRACKIR_CA_BUNDLE", "").strip()
    if preferred_bundle:
        if not os.path.isfile(preferred_bundle):
            raise FileNotFoundError(f"Configured CA bundle not found: {preferred_bundle}")
        log_message(f"Using configured CA bundle: {preferred_bundle}")
        return ssl.create_default_context(cafile=preferred_bundle)

    for bundle_path in CA_BUNDLE_CANDIDATES:
        if os.path.isfile(bundle_path):
            log_message(f"Using detected CA bundle: {bundle_path}")
            return ssl.create_default_context(cafile=bundle_path)

    log_message("No explicit CA bundle found. Falling back to Python default trust store.", "WARNING")
    return ssl.create_default_context()


def get_alert_id(alert: dict) -> str:
    """Build a stable unique ID for an alert."""
    if "id" in alert:
        return str(alert["id"])
    if "_id" in alert:
        return str(alert["_id"])

    source = alert.get("_source", alert)
    rule_id = str(source.get("rule", {}).get("id", ""))
    agent_id = str(source.get("agent", {}).get("id", ""))
    timestamp = str(source.get("timestamp", ""))
    event_id = str(source.get("data", {}).get("win", {}).get("system", {}).get("eventID", ""))
    digest = f"{timestamp}|{rule_id}|{agent_id}|{event_id}"
    return hashlib.sha256(digest.encode("utf-8")).hexdigest()


def get_rule_context(alert: dict) -> Tuple[str, int]:
    source = alert.get("_source", alert)
    rule_id = str(source.get("rule", {}).get("id", ""))
    try:
        rule_level = int(source.get("rule", {}).get("level", 0))
    except (TypeError, ValueError):
        rule_level = 0
    return rule_id, rule_level


def should_forward_alert(alert: dict) -> Tuple[bool, str]:
    """Forward if rule_id is in the explicit allowlist OR level meets the minimum.

    Both conditions are independent â€” setting TRACKIR_RULE_IDS alongside
    TRACKIR_MIN_LEVEL means: forward if rule_id matches OR if level >= min.
    """
    rule_id, rule_level = get_rule_context(alert)

    # Explicit rule ID allowlist â€” always forward regardless of level
    if RULE_ID_FILTER and rule_id in RULE_ID_FILTER:
        return True, f"rule_id {rule_id} in explicit allowlist"

    # Level threshold â€” forward if alert level meets or exceeds minimum
    if rule_level >= MIN_LEVEL:
        return True, f"level {rule_level} >= minimum {MIN_LEVEL}"

    reasons = []
    if RULE_ID_FILTER:
        reasons.append(f"rule_id {rule_id or 'unknown'} not in allowlist")
    reasons.append(f"level {rule_level} < minimum {MIN_LEVEL}")
    return False, " and ".join(reasons)


def send_to_soar(alert: dict) -> bool:
    """Send alert to AlistoIR with retry and backoff."""
    source = alert.get("_source", alert)
    payload = {
        "_index": alert.get("_index", "wazuh-alerts"),
        "_id": alert.get("_id", source.get("id", "")),
        "_source": source,
    }
    json_data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ssl_context = build_ssl_context()
    headers = {
        "Content-Type": "application/json",
        "X-API-Key": SOAR_API_KEY,
        "Content-Length": str(len(json_data)),
        "User-Agent": USER_AGENT,
    }

    if SOAR_TENANT_KEY:
        headers["X-Tenant-Key"] = SOAR_TENANT_KEY

    if WAZUH_SOURCE_ID:
        headers["X-Wazuh-Source"] = WAZUH_SOURCE_ID

    for attempt in range(MAX_RETRIES):
        try:
            request = urllib.request.Request(
                SOAR_URL,
                data=json_data,
                headers=headers,
                method="POST",
            )

            with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT, context=ssl_context) as response:
                raw_body = response.read().decode("utf-8", errors="replace")
                try:
                    result = json.loads(raw_body)
                except json.JSONDecodeError:
                    snippet = raw_body[:MAX_ERROR_BODY_LOG]
                    log_message(f"AlistoIR returned non-JSON response: {snippet}", "ERROR")
                    return False

                if isinstance(result, dict) and result.get("error"):
                    log_message(f"AlistoIR returned an application error: {result['error']}", "ERROR")
                    return False

                log_message(f"Alert forwarded successfully. AlistoIR alert ID: {result.get('alert_id', 'N/A')}")
                return True

        except urllib.error.HTTPError as error:
            body = ""
            try:
                body = error.read().decode("utf-8", errors="replace")
            except Exception:
                body = ""

            if error.code == 429:
                wait_time = (2 ** attempt) + random.uniform(0, 1)
                log_message(
                    f"Rate limited by AlistoIR (429). Retrying in {wait_time:.1f}s [{attempt + 1}/{MAX_RETRIES}]",
                    "WARNING",
                )
                time.sleep(wait_time)
                continue

            snippet = body[:MAX_ERROR_BODY_LOG] if body else error.reason
            log_message(f"HTTP error {error.code}: {snippet}", "ERROR")
            if attempt < MAX_RETRIES - 1:
                time.sleep(5)
                continue
            return False

        except urllib.error.URLError as error:
            log_message(f"Connection error [{attempt + 1}/{MAX_RETRIES}]: {error.reason}", "ERROR")
            if attempt < MAX_RETRIES - 1:
                time.sleep(5 + attempt)
                continue
            return False

        except Exception as error:
            log_message(f"Unexpected forwarding error [{attempt + 1}/{MAX_RETRIES}]: {error}", "ERROR")
            if attempt < MAX_RETRIES - 1:
                time.sleep(5)
                continue
            return False

    return False


def process_alert(connection: sqlite3.Connection, alert: dict) -> bool:
    alert_id = get_alert_id(alert)
    rule_id, rule_level = get_rule_context(alert)
    should_forward, forward_reason = should_forward_alert(alert)

    if DEBUG_ALERTS:
        log_message(f"Observed alert id={alert_id} rule_id={rule_id or 'unknown'} level={rule_level}")

    if not DISABLE_PROCESSED_STATE and db_is_processed(connection, alert_id):
        if DEBUG_ALERTS:
            log_message(f"Skipping alert id={alert_id}: already processed")
        return False

    if not should_forward:
        if DEBUG_ALERTS:
            log_message(f"Skipping alert id={alert_id}: {forward_reason}")
        return False

    if DEBUG_ALERTS:
        log_message(f"Forwarding alert id={alert_id} rule_id={rule_id or 'unknown'}: {forward_reason}")

    if send_to_soar(alert):
        if not DISABLE_PROCESSED_STATE:
            db_mark_processed(connection, alert_id)
        return True

    if DEBUG_ALERTS:
        log_message(f"Forwarding failed for alert id={alert_id} rule_id={rule_id or 'unknown'}", "WARNING")

    return False


def read_state(connection: sqlite3.Connection) -> Tuple[int, int, str]:
    inode = int(db_get_meta(connection, "file_inode", "0") or "0")
    offset = int(db_get_meta(connection, "file_offset", "0") or "0")
    partial = db_get_meta(connection, "partial_line", "")
    return inode, offset, partial


def write_state(connection: sqlite3.Connection, inode: int, offset: int, partial: str) -> None:
    db_set_meta(connection, "file_inode", str(inode))
    db_set_meta(connection, "file_offset", str(offset))
    db_set_meta(connection, "partial_line", partial)


def reset_cursor_state(connection: sqlite3.Connection) -> None:
    connection.execute(
        "DELETE FROM meta WHERE key IN ('file_inode', 'file_offset', 'partial_line')"
    )
    connection.commit()


def safe_json_line_iter(buffer: str) -> Tuple[list, str]:
    """Return complete lines and a trailing partial line buffer."""
    if buffer == "":
        return [], ""

    lines = buffer.splitlines(keepends=True)
    complete = []
    partial = ""

    for line in lines:
        if line.endswith("\n") or line.endswith("\r"):
            complete.append(line.strip())
        else:
            partial = line

    return complete, partial


def tail_file() -> None:
    log_message("Starting hardened Wazuh to AlistoIR forwarder")
    log_message(f"Monitoring alerts file: {WAZUH_ALERTS_FILE}")
    log_message(f"Forwarding to AlistoIR: {SOAR_URL}")
    if not SOAR_API_KEY:
        log_message("TRACKIR_SOAR_API_KEY is empty. Requests will be rejected by AlistoIR.", "WARNING")
    if SOAR_TENANT_KEY:
        log_message("Tenant-scoped ingestion: enabled (X-Tenant-Key will be sent)")
    else:
        log_message(
            "Tenant-scoped ingestion: disabled. Set TRACKIR_TENANT_KEY when AlistoIR requires X-Tenant-Key.",
            "WARNING",
        )
    if WAZUH_SOURCE_ID:
        log_message(f"Wazuh source header   : {WAZUH_SOURCE_ID}")
    log_message(f"Minimum rule level : {MIN_LEVEL} (forward if level >= {MIN_LEVEL})")
    if RULE_ID_FILTER:
        log_message("Rule ID allowlist  : " + ", ".join(sorted(RULE_ID_FILTER)) + " (always forward these rule IDs regardless of level)")
    log_message(
        "Processed alert state: disabled (offset tracking stays enabled)"
        if DISABLE_PROCESSED_STATE
        else "Processed alert state: enabled"
    )
    if DEBUG_ALERTS:
        log_message("Per-alert debug logging: enabled")

    connection = db_connect()
    if not DISABLE_PROCESSED_STATE:
        pruned = db_prune_processed(connection)
        if pruned:
            log_message(f"Pruned {pruned} expired processed alert IDs")
    if RESET_CURSOR_ON_START:
        reset_cursor_state(connection)
        log_message("Reset saved alerts.json cursor state on startup.")

    while not os.path.exists(WAZUH_ALERTS_FILE):
        log_message(f"Waiting for alerts file: {WAZUH_ALERTS_FILE}", "WARNING")
        time.sleep(5)

    inode, offset, partial = read_state(connection)
    if START_AT_END_ON_FRESH_RUN and inode == 0 and offset == 0 and partial == "":
        try:
            stats = os.stat(WAZUH_ALERTS_FILE)
            inode = int(getattr(stats, "st_ino", 0))
            offset = int(stats.st_size)
            write_state(connection, inode, offset, partial)
            log_message("No saved offset found. Starting from end of alerts.json for live monitoring.")
        except Exception as error:
            log_message(f"Could not initialize end-of-file start position: {error}", "WARNING")
    log_message("Monitoring started. Press Ctrl+C to stop.")

    try:
        while True:
            try:
                stats = os.stat(WAZUH_ALERTS_FILE)
                current_inode = int(getattr(stats, "st_ino", 0))
                current_size = int(stats.st_size)

                if inode and current_inode != inode:
                    log_message("Detected alerts file rotation. Resetting read position.")
                    offset = 0
                    partial = ""

                if current_size < offset:
                    log_message("Detected alerts file truncation. Resetting read position.")
                    offset = 0
                    partial = ""

                with open(WAZUH_ALERTS_FILE, "r", encoding="utf-8", errors="replace") as handle:
                    handle.seek(offset)
                    chunk = handle.read()
                    new_offset = handle.tell()

                if chunk:
                    lines, partial = safe_json_line_iter(partial + chunk)
                    for line in lines:
                        if not line:
                            continue
                        try:
                            alert = json.loads(line)
                        except json.JSONDecodeError:
                            log_message("Skipping malformed alert line while preserving stream state", "WARNING")
                            continue

                        forwarded = process_alert(connection, alert)
                        if forwarded and FORWARD_DELAY > 0:
                            time.sleep(FORWARD_DELAY)

                    offset = new_offset
                    inode = current_inode
                    write_state(connection, inode, offset, partial)
                else:
                    inode = current_inode
                    write_state(connection, inode, offset, partial)

                time.sleep(CHECK_INTERVAL)

            except FileNotFoundError:
                log_message("Alerts file not found. Waiting for Wazuh to recreate it.", "WARNING")
                offset = 0
                partial = ""
                time.sleep(5)
            except Exception as error:
                log_message(f"Tail loop error: {error}", "ERROR")
                time.sleep(5)

    except KeyboardInterrupt:
        log_message("Forwarder stopped by operator")
    finally:
        connection.close()


def run_once() -> None:
    log_message("Processing alerts file in one-time mode")
    connection = db_connect()
    if DISABLE_PROCESSED_STATE:
        log_message("Processed alert state is disabled for this run")
    else:
        pruned = db_prune_processed(connection)
        if pruned:
            log_message(f"Pruned {pruned} expired processed alert IDs")
    if DEBUG_ALERTS:
        log_message("Per-alert debug logging: enabled for one-time mode")

    processed_count = 0

    if not os.path.exists(WAZUH_ALERTS_FILE):
        log_message(f"Alerts file not found: {WAZUH_ALERTS_FILE}", "ERROR")
        connection.close()
        return

    with open(WAZUH_ALERTS_FILE, "r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue
            if process_alert(connection, alert):
                processed_count += 1

    log_message(f"One-time mode completed. Forwarded {processed_count} alerts.")
    connection.close()


def validate_config() -> bool:
    missing = []
    if not SOAR_URL:
        missing.append("TRACKIR_SOAR_URL")
    if not SOAR_API_KEY:
        missing.append("TRACKIR_SOAR_API_KEY")

    if missing:
        log_message("Missing required environment variables: " + ", ".join(missing), "ERROR")
        return False

    return True


def main() -> int:
    if not validate_config():
        return 1

    if len(sys.argv) > 1 and sys.argv[1] == "--once":
        run_once()
        return 0

    tail_file()
    return 0


if __name__ == "__main__":
    sys.exit(main())
