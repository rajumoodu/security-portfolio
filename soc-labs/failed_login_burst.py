
"""
failed_login_burst.py
---------------------
Detect bursts of failed logins within a sliding time window.
- Works out of the box on the included sample_auth.log (Linux/sshd-like lines).
- Groups by IP, user, or IP+user and raises an alert when a threshold is exceeded.

Usage:
  python failed_login_burst.py --log sample_auth.log --window 5 --threshold 5 --group-by ip
  python failed_login_burst.py --log sample_auth.log --window 10 --threshold 15 --group-by user

Outputs:
  - burst_report.csv
  - burst_report.json
"""
import argparse
import re
import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone
from collections import defaultdict, deque
import json
import csv

TS_PATTERNS = [
    # ISO-ish: 2025-08-16 12:34:56
    (re.compile(r'^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})'), "%Y-%m-%d %H:%M:%S"),
    # Syslog: Aug 16 12:34:56
    (re.compile(r'^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'), "%b %d %H:%M:%S"),
]

SSH_FAIL_RE = re.compile(
    r'Failed password for (invalid user\s+)?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})'
)

def parse_timestamp(line: str) -> datetime | None:
    for rx, fmt in TS_PATTERNS:
        m = rx.search(line)
        if m:
            ts_str = m.group('ts').replace('T', ' ')
            try:
                # If year missing (syslog), assume current year
                if fmt == "%b %d %H:%M:%S":
                    this_year = datetime.now().year
                    ts = datetime.strptime(ts_str, fmt).replace(year=this_year)
                else:
                    ts = datetime.strptime(ts_str, fmt)
                return ts
            except Exception:
                continue
    return None

def parse_event(line: str):
    ts = parse_timestamp(line)
    if ts is None:
        return None
    m = SSH_FAIL_RE.search(line)
    if not m:
        return None
    user = m.group('user')
    ip = m.group('ip')
    return {"ts": ts, "user": user, "ip": ip}

def group_key(evt, mode: str) -> str:
    if mode == "ip":
        return evt["ip"]
    elif mode == "user":
        return evt["user"]
    elif mode == "ip_user":
        return f'{evt["ip"]}|{evt["user"]}'
    else:
        raise ValueError("group-by must be one of: ip, user, ip_user")

def main():
    ap = argparse.ArgumentParser(description="Detect bursts of failed logins in logs.")
    ap.add_argument("--log", required=True, help="Path to auth log")
    ap.add_argument("--window", type=int, default=5, help="Time window in minutes (sliding)")
    ap.add_argument("--threshold", type=int, default=10, help="Burst threshold (count)")
    ap.add_argument("--group-by", choices=["ip", "user", "ip_user"], default="ip")
    ap.add_argument("--csv-out", default="burst_report.csv", help="CSV output path")
    ap.add_argument("--json-out", default="burst_report.json", help="JSON output path")
    args = ap.parse_args()

    path = Path(args.log)
    if not path.exists():
        print(f"[ERROR] Log not found: {path}", file=sys.stderr)
        sys.exit(2)

    events = []
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            evt = parse_event(line)
            if evt:
                events.append(evt)

    events.sort(key=lambda e: e["ts"])

    # Sliding window bursts per key
    window = timedelta(minutes=args.window)
    deques = defaultdict(deque)
    last_alert_time = {}
    alerts = []

    for evt in events:
        key = group_key(evt, args.group_by)
        q = deques[key]
        # push current ts
        q.append(evt["ts"])
        # pop any outside the window
        min_ts = evt["ts"] - window
        while q and q[0] < min_ts:
            q.popleft()
        count = len(q)

        if count >= args.threshold:
            # Avoid spamming: only alert again if it's a new window crossing
            prev = last_alert_time.get(key)
            if prev is None or evt["ts"] - prev >= window / 2:
                alerts.append({
                    "group": key,
                    "group_by": args.group_by,
                    "count_in_window": count,
                    "window_minutes": args.window,
                    "threshold": args.threshold,
                    "window_start": q[0].strftime("%Y-%m-%d %H:%M:%S"),
                    "event_time": evt["ts"].strftime("%Y-%m-%d %H:%M:%S"),
                    "window_end": evt["ts"].strftime("%Y-%m-%d %H:%M:%S"),
                })
                last_alert_time[key] = evt["ts"]

    # Write CSV
    with open(args.csv_out, "w", newline="", encoding="utf-8") as cf:
        writer = csv.DictWriter(cf, fieldnames=[
            "group","group_by","count_in_window","window_minutes","threshold",
            "window_start","event_time","window_end"
        ])
        writer.writeheader()
        for a in alerts:
            writer.writerow(a)

    # Write JSON
    with open(args.json_out, "w", encoding="utf-8") as jf:
        json.dump({"alerts": alerts, "total_parsed_events": len(events)}, jf, indent=2)

    print(f"Parsed events: {len(events)}")
    print(f"Alerts generated: {len(alerts)}")
    print(f"CSV:  {args.csv_out}")
    print(f"JSON: {args.json_out}")

if __name__ == "__main__":
    main()
