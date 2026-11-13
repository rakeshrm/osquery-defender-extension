#!/usr/bin/env python3
"""Summarize soak-test results downloaded by `gce-soak.sh collect`.

Usage: python3 -I analyze.py <results-dir>
Expects <results-dir>/<HOST>/latest/{monitor.csv, defender-events.log,
boots.log, osquery/*.log}. Standard library only.

Verdict per host (PASS / CHECK) is based on:
  - extension restarts (watchdog kills or crashes) and gaps where it was not running
  - memory growth of the extension between the first and last 6 hours
  - status rows with an error, or quick_check other than ok
  - Defender warnings/errors, and whether the database kept being updated
  - osquery warnings/errors mentioning the extension or its tables
"""
import collections
import csv
import glob
import json
import os
import statistics
import sys
from datetime import datetime, timedelta


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00")) if s else None


def num(s):
    try:
        return float(s)
    except (TypeError, ValueError):
        return None


def read_lines(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8-sig", errors="replace") as f:
        return [line.rstrip("\n") for line in f]


def find(base, pattern):
    """All files under base whose name matches pattern (glob, recursive)."""
    return sorted(glob.glob(os.path.join(base, "**", pattern), recursive=True))


def analyze_host(host, base):
    print(f"\n=== {host}")
    issues = []

    mon_files = find(base, "monitor.csv")
    rows = []
    for p in mon_files:
        with open(p, encoding="utf-8-sig", errors="replace") as f:
            rows += list(csv.DictReader(f))
    rows = [r for r in rows if r.get("ts_utc")]
    rows.sort(key=lambda r: r["ts_utc"])
    if not rows:
        print("  no monitor samples")
        return ["no monitor samples"]

    t0, t1 = ts(rows[0]["ts_utc"]), ts(rows[-1]["ts_utc"])
    print(f"  window      {t0:%Y-%m-%d %H:%M} -> {t1:%Y-%m-%d %H:%M} UTC ({(t1 - t0).total_seconds() / 3600:.1f} h, {len(rows)} samples)")
    print(f"  defender    engine {sorted({r['engine'] for r in rows if r['engine']})} platform {sorted({r['platform'] for r in rows if r['platform']})}")
    print(f"  signatures  {rows[0]['signatures']} -> {rows[-1]['signatures']}  rtp={sorted({r['rtp'] for r in rows})}")

    boots = [line for line in read_lines(next(iter(find(base, "boots.log")), "")) if line]
    if len(boots) > 1:
        print(f"  reboots     {len(boots) - 1} (Windows Update or maintenance)")

    starts = [r["ext_start_utc"] for r in rows if r["ext_start_utc"]]
    distinct = list(dict.fromkeys(starts))
    missing = sum(1 for r in rows if not r["ext_pid"])
    print(f"  extension   {len(distinct)} process lifetime(s); {missing} sample(s) with no extension process")
    if len(distinct) > len(boots):
        issues.append(f"extension restarted {len(distinct) - len(boots)} time(s) beyond reboots")
    if missing > 2:
        issues.append(f"extension not running in {missing} samples")

    mem = [(ts(r["ts_utc"]), num(r["ext_private_mb"])) for r in rows if num(r["ext_private_mb"]) is not None]
    if mem:
        vals = [v for _, v in mem]
        first = [v for t, v in mem if t <= t0 + timedelta(hours=6)]
        last = [v for t, v in mem if t >= t1 - timedelta(hours=6)]
        growth = statistics.median(last) - statistics.median(first)
        print(f"  ext memory  private MB min {min(vals):.1f} median {statistics.median(vals):.1f} max {max(vals):.1f}; "
              f"median first 6h {statistics.median(first):.1f} -> last 6h {statistics.median(last):.1f} ({growth:+.1f})")
        if growth > 20 or max(vals) > 150:
            issues.append(f"extension memory growth {growth:+.1f} MB / max {max(vals):.1f} MB")
        handles = [num(r["ext_handles"]) for r in rows if num(r["ext_handles"]) is not None]
        print(f"  ext handles min {min(handles):.0f} max {max(handles):.0f}")
        if max(handles) - min(handles) > 200:
            issues.append(f"extension handle growth {min(handles):.0f} -> {max(handles):.0f}")

    mtimes = {r["db_mtime_utc"] for r in rows if r["db_mtime_utc"]} | {r["wal_mtime_utc"] for r in rows if r["wal_mtime_utc"]}
    print(f"  database    {len(mtimes)} distinct db/wal modification times; db size {rows[0]['db_size']} -> {rows[-1]['db_size']}")
    if len(mtimes) < 3:
        issues.append("Defender database barely changed (is Defender writing it?)")

    def_errors = sum(int(num(r["def_errors_new"]) or 0) for r in rows)
    def_events = sum(int(num(r["def_events_new"]) or 0) for r in rows)
    print(f"  def events  {def_events} warnings/errors ({def_errors} errors) in Defender/Operational")
    ev = [line for p in find(base, "defender-events.log") for line in read_lines(p)]
    top = collections.Counter(line.split(" ", 3)[1] if len(line.split(" ", 3)) > 1 else "?" for line in ev)
    for k, v in top.most_common(5):
        sample = next(line for line in ev if f" {k} " in line)
        print(f"     {v:>4} x {k}: {sample.split(' ', 3)[-1][:140]}")
    if def_errors:
        issues.append(f"{def_errors} Defender error events (check for database/IO errors)")

    status_rows, status_errors, qc_bad, counts = 0, collections.Counter(), collections.Counter(), {}
    layouts = set()
    for p in find(base, "osqueryd.results.log*") + find(base, "osqueryd.snapshots.log*"):
        for line in read_lines(p):
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            name = rec.get("name", "")
            snap = rec.get("snapshot") or []
            if name == "soak_status":
                for r in snap:
                    status_rows += 1
                    if r.get("error"):
                        status_errors[r["error"][:120]] += 1
                    if r.get("quick_check") not in ("ok", None):
                        qc_bad[r.get("quick_check", "")[:120]] += 1
            elif name == "soak_counts":
                counts = {r["t"]: r["n"] for r in snap}
            elif name == "soak_tables":
                layouts |= {r["table_name"] for r in snap if "nventory" in r.get("table_name", "")}
    print(f"  status      {status_rows} snapshots, {sum(status_errors.values())} with error, {sum(qc_bad.values())} quick_check not ok")
    for e, n in status_errors.most_common(3):
        print(f"     {n:>4} x {e}")
    if status_rows == 0:
        issues.append("no soak_status results logged (osqueryd/extension not answering?)")
    if status_errors or qc_bad:
        issues.append("status reported errors or quick_check failures")
    if counts:
        print("  last counts " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    if layouts:
        print(f"  inventory   tables present: {sorted(layouts)}")

    warn = []
    for p in find(base, "osqueryd.WARNING*") + find(base, "osqueryd.ERROR*"):
        warn += [line for line in read_lines(p) if "defender" in line.lower() or "extension" in line.lower()]
    print(f"  osquery     {len(warn)} warning/error lines mentioning the extension")
    for line in collections.Counter(w[w.find("]") + 1:].strip()[:140] for w in warn).most_common(5):
        print(f"     {line[1]:>4} x {line[0]}")
    if warn:
        issues.append(f"{len(warn)} osquery warnings/errors about the extension")

    print("  verdict     " + ("PASS" if not issues else "CHECK: " + "; ".join(issues)))
    return issues


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    root = sys.argv[1]
    hosts = sorted(d for d in os.listdir(root) if os.path.isdir(os.path.join(root, d, "latest")))
    if not hosts:
        sys.exit(f"no <host>/latest directories under {root}")
    results = {h: analyze_host(h, os.path.join(root, h, "latest")) for h in hosts}
    print("\nOverall: " + ("PASS" if not any(results.values()) else "CHECK " + ", ".join(h for h, i in results.items() if i)))


if __name__ == "__main__":
    main()
