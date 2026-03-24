#!/usr/bin/env python3
import argparse
import csv
import re
from pathlib import Path

FILENAME_RE = re.compile(r"^capturaAgente(?P<agent>[A-Za-z]+)(?P<dur>\d+m|1h)(?P<run>\d+)\.pcapng$")
DUR_TARGET_S = {"5m": 300, "15m": 900, "60m": 3600, "1h": 3600}

def parse_duration_label(filename: str):
    m = FILENAME_RE.match(filename)
    return m.group("dur") if m else None

def to_int(x, default=0):
    try:
        return int(float(x))
    except Exception:
        return default

def to_float(x, default=None):
    try:
        return float(x)
    except Exception:
        return default

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True, help="captures_summary.csv path")
    ap.add_argument("--tol", type=float, default=0.05, help="duration tolerance fraction (default ±5%)")
    ap.add_argument("--out", default="qc_report.txt", help="output report file")
    args = ap.parse_args()

    csv_path = Path(args.csv).expanduser().resolve()
    out_path = Path(args.out).expanduser().resolve()

    rows = []
    with csv_path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append(r)

    to_recapture = []
    suspicious = []

    for r in rows:
        fn = (r.get("filename") or "").strip()
        err = (r.get("error") or "").strip()
        trunc = to_int(r.get("capinfos_truncated", 0), 0)

        totals_cons = (r.get("totals_consistent") or "").strip()
        totals_cons_i = to_int(totals_cons, -1) if totals_cons != "" else -1

        dur_s = to_float((r.get("capture_duration_s") or "").strip(), None)
        dur_label = parse_duration_label(fn)
        dur_reason = None
        if dur_s is not None and dur_label in DUR_TARGET_S:
            target = DUR_TARGET_S[dur_label]
            lo = target * (1 - args.tol)
            hi = target * (1 + args.tol)
            if not (lo <= dur_s <= hi):
                dur_reason = f"duration_out_of_range({dur_s:.1f}s not in [{lo:.1f},{hi:.1f}])"

        reasons = []
        if trunc == 1:
            reasons.append("capinfos_truncated=1")
        if err:
            reasons.append(f"error={err}")

        if reasons:
            if dur_reason:
                reasons.append(dur_reason)
            to_recapture.append((fn, reasons))
            continue

        soft = []
        if totals_cons_i == 0:
            soft.append("totals_consistent=0")
        if dur_reason:
            soft.append(dur_reason)
        if soft:
            suspicious.append((fn, soft))

    lines = []
    lines.append(f"QC report for: {csv_path}")
    lines.append("")
    lines.append("== Captures to re-capture (hard failures) ==")
    if not to_recapture:
        lines.append("None.")
    else:
        for fn, reasons in sorted(to_recapture):
            lines.append(f"- {fn}: " + "; ".join(reasons))

    lines.append("")
    lines.append("== Suspicious captures (soft flags; review) ==")
    if not suspicious:
        lines.append("None.")
    else:
        for fn, reasons in sorted(suspicious):
            lines.append(f"- {fn}: " + "; ".join(reasons))

    out_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"[ok] Wrote report to {out_path}")

    if to_recapture:
        print("\nCaptures to re-capture:")
        for fn, reasons in sorted(to_recapture):
            print(f"  {fn} -> {', '.join(reasons)}")
    else:
        print("\nNo captures require re-capture based on hard-failure rules.")

if __name__ == "__main__":
    main()
