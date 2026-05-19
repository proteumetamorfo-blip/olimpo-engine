import re
from datetime import datetime

_IPV4_PATTERN = re.compile(
    r"^(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"
    r"(\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}$"
)

def _clean_string(value):
    return " ".join(str(value).split())

def _normalize_event(event):
    return _clean_string(event).lower().replace(" ", "_")

def _is_valid_ipv4(ip):
    return bool(_IPV4_PATTERN.match(ip.strip()))

def _parse_timestamp(ts_str):
    try:
        return datetime.fromisoformat(ts_str)
    except (ValueError, TypeError):
        return None

def transform(raw_events):
    clean_events = []
    quarantined = []
    for raw in raw_events:
        record = dict(raw)
        errors = []
        ip_raw = record.get("ip", "")
        ip_clean = _clean_string(ip_raw)
        if not _is_valid_ipv4(ip_clean):
            errors.append(f"IP invalido: '{ip_raw}'")
        else:
            record["ip"] = ip_clean
        event_raw = record.get("event", "")
        if not event_raw or not str(event_raw).strip():
            errors.append("Campo event vazio.")
        else:
            record["event"] = _normalize_event(event_raw)
        record["route"] = _clean_string(record.get("route", "")) or "/"
        ts_raw = record.get("timestamp", "")
        parsed_ts = _parse_timestamp(ts_raw)
        if parsed_ts is None:
            errors.append(f"Timestamp invalido: '{ts_raw}'")
        else:
            record["timestamp"] = parsed_ts.strftime("%Y-%m-%d %H:%M:%S")
            record["_parsed_ts"] = parsed_ts
        if errors:
            record["reject_reason"] = " | ".join(errors)
            quarantined.append(record)
        else:
            clean_events.append(record)
    return clean_events, quarantined
