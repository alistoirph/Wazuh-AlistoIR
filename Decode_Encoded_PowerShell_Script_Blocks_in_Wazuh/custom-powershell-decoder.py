#!/usr/bin/env python3

import base64
import gzip
import json
import os
import re
import sys
import time
import zlib
from datetime import datetime, timezone

try:
    import fcntl  # type: ignore
except ImportError:  # pragma: no cover - used for local Windows testing only
    fcntl = None

OUTPUT_LOG = os.environ.get("POWERSHELL_DECODER_OUTPUT", "/var/log/wazuh-powershell-decoded.json")
DEBUG_LOG = os.environ.get("POWERSHELL_DECODER_DEBUG_LOG", "/var/log/wazuh-powershell-decoder-debug.log")
MONITOR_ALERTS_FILE = os.environ.get("POWERSHELL_DECODER_ALERTS_FILE", "/var/ossec/logs/alerts/alerts.json")
MONITOR_STATE_FILE = os.environ.get(
    "POWERSHELL_DECODER_STATE_FILE", "/var/ossec/integrations/powershell-decoder-monitor.state.json"
)
MONITOR_POLL_SECONDS = float(os.environ.get("POWERSHELL_DECODER_POLL_SECONDS", "2"))
MAX_DECODE_DEPTH = int(os.environ.get("POWERSHELL_DECODER_MAX_DEPTH", "5"))
MAX_DECODE_TEXT = int(os.environ.get("POWERSHELL_DECODER_MAX_TEXT", "12000"))

BASE64_HINT_RE = re.compile(
    r"(?i)(?:-enc|-encodedcommand|frombase64string\s*\()\s*['\"]?([A-Za-z0-9+/=]{20,})"
)
GENERIC_BASE64_RE = re.compile(r"\b[A-Za-z0-9+/=]{80,}\b")

URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.I)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")
DOMAIN_EXCLUSIONS = {
    "net.webclient",
    "system.io",
    "system.net",
    "system.text",
    "system.security",
    "microsoft.powershell",
}


def get_nested(data, path, default=""):
    current = data
    for key in path.split("."):
        if isinstance(current, dict):
            current = current.get(key, default)
        else:
            return default
    return current


def normalize_base64(value):
    value = value.strip().strip("'\"")
    value = re.sub(r"\s+", "", value)
    missing_padding = len(value) % 4
    if missing_padding:
        value += "=" * (4 - missing_padding)
    return value


def try_base64_decode(value):
    try:
        return base64.b64decode(normalize_base64(value), validate=False)
    except Exception:
        return None


def try_decompress(data):
    for fn in (
        lambda x: gzip.decompress(x),
        lambda x: zlib.decompress(x),
        lambda x: zlib.decompress(x, -zlib.MAX_WBITS),
    ):
        try:
            return fn(data)
        except Exception:
            pass
    return None


def is_readable(text):
    if not text:
        return False

    printable = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
    ratio = printable / max(len(text), 1)

    keywords = (
        "powershell",
        "iex",
        "invoke-expression",
        "invoke-webrequest",
        "invoke-restmethod",
        "downloadstring",
        "downloadfile",
        "frombase64string",
        "new-object",
        "net.webclient",
        "amsi",
        "bypass",
        "hidden",
        "start-process",
        "http",
        "https",
        "add-mppreference",
        "set-mppreference",
    )

    lowered = text.lower()
    return ratio > 0.75 or any(keyword in lowered for keyword in keywords)


def bytes_to_text(data):
    for encoding in ("utf-16le", "utf-8", "utf-16", "latin-1"):
        try:
            text = data.decode(encoding)
            if is_readable(text):
                return text
        except Exception:
            pass
    return None


def extract_iocs(text):
    domains = []
    for candidate in DOMAIN_RE.findall(text):
        lowered = candidate.lower()
        if lowered in DOMAIN_EXCLUSIONS:
            continue
        domains.append(candidate)

    return {
        "urls": sorted(set(URL_RE.findall(text))),
        "ips": sorted(set(IP_RE.findall(text))),
        "domains": sorted(set(domains)),
        "hashes": sorted(set(HASH_RE.findall(text))),
    }


def classify_risk(decoded_script):
    lowered = decoded_script.lower()
    high_patterns = [
        "iex",
        "invoke-expression",
        "net.webclient",
        "downloadstring",
        "downloadfile",
        "invoke-webrequest",
        "invoke-restmethod",
        "start-bitstransfer",
        "bitsadmin",
        "certutil",
        "mshta",
        "rundll32",
        "regsvr32",
        "scrobj.dll",
        "frombase64string",
        "add-mppreference",
        "set-mppreference",
        "disableantispyware",
        "amsi",
        "bypass",
        "encodedcommand",
        "hidden",
        "start-process",
    ]
    hits = [pattern for pattern in high_patterns if pattern in lowered]

    if len(hits) >= 3:
        return "high", hits
    if hits:
        return "medium", hits
    return "low", hits


def truncate_text(text):
    if len(text) <= MAX_DECODE_TEXT:
        return text
    return text[:MAX_DECODE_TEXT] + "\n...<truncated>..."


def recursive_decode(text, max_depth=MAX_DECODE_DEPTH):
    results = []
    current_text = text
    seen_decoded = set()

    for depth in range(1, max_depth + 1):
        candidates = BASE64_HINT_RE.findall(current_text) + GENERIC_BASE64_RE.findall(current_text)
        candidates = sorted(set(candidates), key=len, reverse=True)
        if not candidates:
            break

        decoded_this_round = False

        for candidate in candidates:
            raw = try_base64_decode(candidate)
            if not raw:
                continue

            compression = None
            decompressed = try_decompress(raw)
            if decompressed is not None:
                compression = "gzip/zlib"
                raw = decompressed

            decoded_text = bytes_to_text(raw)
            if not decoded_text:
                continue

            normalized_decoded = decoded_text.strip()
            if normalized_decoded in seen_decoded:
                continue

            seen_decoded.add(normalized_decoded)
            results.append(
                {
                    "depth": depth,
                    "encoded_sample": candidate[:160],
                    "decoded": truncate_text(decoded_text),
                    "compression": compression,
                    "iocs": extract_iocs(decoded_text),
                }
            )
            current_text = decoded_text
            decoded_this_round = True
            break

        if not decoded_this_round:
            break

    return results


def build_payload(alert, decoded_layers):
    scriptblock = get_nested(alert, "data.win.eventdata.scriptBlockText", "")
    commandline = get_nested(alert, "data.win.eventdata.commandLine", "")
    process_cmd = get_nested(alert, "data.win.eventdata.processCommandLine", "")
    agent_name = get_nested(alert, "agent.name", "")
    agent_id = get_nested(alert, "agent.id", "")
    rule_id = get_nested(alert, "rule.id", "")
    rule_description = get_nested(alert, "rule.description", "")
    event_id = get_nested(alert, "data.win.system.eventID", "")

    last_decoded = decoded_layers[-1]["decoded"] if decoded_layers else ""
    risk, suspicious_hits = classify_risk(last_decoded)

    iocs = {"urls": [], "ips": [], "domains": [], "hashes": []}
    for layer in decoded_layers:
        for key, values in layer.get("iocs", {}).items():
            iocs[key] = sorted(set(iocs.get(key, []) + values))

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "integration": "powershell_decoder",
        "source": "wazuh",
        "agent_name": agent_name,
        "agent_id": agent_id,
        "original_rule_id": str(rule_id),
        "original_rule_description": rule_description,
        "original_event_id": str(event_id),
        "decode_depth": len(decoded_layers),
        "risk": risk,
        "suspicious_hits": suspicious_hits,
        "decoded_script": last_decoded,
        "decoded_layers": decoded_layers,
        "iocs": iocs,
        "original_scriptblock": truncate_text(scriptblock),
        "original_commandline": truncate_text(commandline),
        "original_process_commandline": truncate_text(process_cmd),
    }


def process_alert(alert):
    scriptblock = get_nested(alert, "data.win.eventdata.scriptBlockText", "")
    commandline = get_nested(alert, "data.win.eventdata.commandLine", "")
    process_cmd = get_nested(alert, "data.win.eventdata.processCommandLine", "")

    content = "\n".join(part for part in (scriptblock, commandline, process_cmd) if part)
    append_debug_log(
        f"content len={len(content)} has_scriptblock={bool(scriptblock)} has_commandline={bool(commandline)} "
        f"has_process_cmd={bool(process_cmd)} rule_id={get_nested(alert, 'rule.id', '')} "
        f"agent={get_nested(alert, 'agent.name', '')}"
    )
    decoded_layers = recursive_decode(content)
    if not decoded_layers:
        append_debug_log("skip no-decoded-layers")
        return 0

    payload = build_payload(alert, decoded_layers)
    append_json_log(payload)
    append_debug_log(
        f"decoded success depth={payload.get('decode_depth')} risk={payload.get('risk')} "
        f"agent={payload.get('agent_name')} original_rule_id={payload.get('original_rule_id')}"
    )
    return 0


def append_json_log(record):
    line = json.dumps(record, ensure_ascii=False)
    with open(OUTPUT_LOG, "a", encoding="utf-8") as handle:
        if fcntl is not None:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        handle.write(line + "\n")
        handle.flush()
        os.fsync(handle.fileno())
        if fcntl is not None:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def append_debug_log(message):
    timestamp = datetime.now(timezone.utc).isoformat()
    try:
        debug_dir = os.path.dirname(DEBUG_LOG)
        if debug_dir:
            os.makedirs(debug_dir, exist_ok=True)

        with open(DEBUG_LOG, "a", encoding="utf-8") as handle:
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            handle.write(f"{timestamp} {message}\n")
            handle.flush()
            os.fsync(handle.fileno())
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    except Exception:
        pass


def load_monitor_state():
    try:
        with open(MONITOR_STATE_FILE, "r", encoding="utf-8") as handle:
            state = json.load(handle)
            if isinstance(state, dict):
                return {
                    "inode": state.get("inode"),
                    "offset": int(state.get("offset", 0)),
                }
    except Exception:
        pass
    return {"inode": None, "offset": 0}


def save_monitor_state(inode, offset):
    state = {"inode": inode, "offset": offset}
    with open(MONITOR_STATE_FILE, "w", encoding="utf-8") as handle:
        json.dump(state, handle)
        handle.flush()
        os.fsync(handle.fileno())


def should_process_monitored_alert(alert):
    rule_id = str(get_nested(alert, "rule.id", ""))
    return (
        rule_id in {"91809", "110420"}
        and str(get_nested(alert, "data.win.system.eventID", "")) == "4104"
    )


def run_monitor():
    append_debug_log(
        f"monitor start alerts_file={MONITOR_ALERTS_FILE} state_file={MONITOR_STATE_FILE} poll={MONITOR_POLL_SECONDS}"
    )
    state = load_monitor_state()

    while True:
        try:
            st = os.stat(MONITOR_ALERTS_FILE)
            inode = getattr(st, "st_ino", None)
            size = st.st_size

            if state["inode"] != inode or state["offset"] > size:
                state = {"inode": inode, "offset": 0}

            with open(MONITOR_ALERTS_FILE, "r", encoding="utf-8", errors="ignore") as handle:
                handle.seek(state["offset"])

                while True:
                    line_start = handle.tell()
                    line = handle.readline()
                    if not line:
                        break

                    if not line.endswith("\n"):
                        handle.seek(line_start)
                        break

                    state["offset"] = handle.tell()
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        alert = json.loads(line)
                    except Exception as exc:
                        append_debug_log(f"monitor skip json-error exc={exc!r}")
                        continue

                    if not should_process_monitored_alert(alert):
                        continue

                    append_debug_log(
                        f"monitor process rule_id={get_nested(alert, 'rule.id', '')} "
                        f"agent={get_nested(alert, 'agent.name', '')}"
                    )
                    process_alert(alert)

            save_monitor_state(state["inode"], state["offset"])
        except Exception as exc:
            append_debug_log(f"monitor error exc={exc!r}")

        time.sleep(MONITOR_POLL_SECONDS)


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "--monitor":
        run_monitor()
        return 0

    if len(sys.argv) < 2:
        append_debug_log("skip no-args")
        return 0

    alert_file = sys.argv[1]
    append_debug_log(f"start alert_file={alert_file} argv={sys.argv[1:]}")

    try:
        with open(alert_file, "r", encoding="utf-8") as handle:
            alert = json.load(handle)
    except Exception as exc:
        append_debug_log(f"error reading alert_file={alert_file} exc={exc!r}")
        return 0

    return process_alert(alert)


if __name__ == "__main__":
    sys.exit(main())
