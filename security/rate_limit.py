from datetime import datetime, timedelta
from collections import defaultdict

MONITORED_EVENTS = {"login_failed", "contact_submit"}
MAX_EVENTS_PER_WINDOW = 5
WINDOW_SECONDS = 300

def _make_threat(ip, rule, detail, severity):
    return {
        "ip": ip, "rule": rule, "detail": detail,
        "severity": severity,
        "detected_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
    }

def analyze(clean_events):
    groups = defaultdict(list)
    for ev in clean_events:
        if ev.get("event") in MONITORED_EVENTS:
            groups[(ev["ip"], ev["event"])].append(ev["_parsed_ts"])

    abusive_ips = {}
    for (ip, event_type), timestamps in groups.items():
        timestamps_sorted = sorted(timestamps)
        for i in range(len(timestamps_sorted)):
            window_start = timestamps_sorted[i]
            window_end = window_start + timedelta(seconds=WINDOW_SECONDS)
            events_in_window = [t for t in timestamps_sorted[i:] if t <= window_end]
            if len(events_in_window) > MAX_EVENTS_PER_WINDOW:
                abusive_ips[ip] = {
                    "ip": ip, "event_type": event_type,
                    "count": len(events_in_window),
                    "window_start": window_start.strftime("%Y-%m-%d %H:%M:%S"),
                    "window_end": window_end.strftime("%Y-%m-%d %H:%M:%S"),
                    "reason": f"{len(events_in_window)}x '{event_type}' em {WINDOW_SECONDS}s (limite: {MAX_EVENTS_PER_WINDOW})",
                    "detected_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                }
                break

    flagged_events = []
    abusive_ip_set = set(abusive_ips.keys())
    for ev in clean_events:
        flagged = dict(ev)
        flagged.pop("_parsed_ts", None)
        if ev["ip"] in abusive_ip_set:
            flagged["alert_level"] = "CRITICAL"
        elif ev.get("event") in MONITORED_EVENTS:
            flagged["alert_level"] = "WARNING"
        else:
            flagged["alert_level"] = "OK"
        flagged_events.append(flagged)

    return flagged_events, list(abusive_ips.values())
