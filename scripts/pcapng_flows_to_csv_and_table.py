#!/usr/bin/env python3
"""
pcapng_flows_to_csv_and_table.py

Compute flow-structure indicators from PCAPNG captures and generate:
  (i) a per-capture CSV with flow metrics, and
  (ii) a LaTeX table (median [IQR]) aggregated by (profile, duration).

Flow definition
---------------
Bidirectional 5-tuple over TCP/UDP:
  key = (proto, endpointA, endpointB)
where endpoint = (ip, port) and (endpointA, endpointB) is an order-invariant pair
(sorted lexicographically) so that both directions map to the same flow.

Per-flow metrics (per capture)
------------------------------
- bytes_per_flow: sum of frame.len over packets in the flow
- pkts_per_flow: packet count in the flow
- duration_s: last_ts - first_ts

Per-capture indicators
----------------------
- flows: number of bidirectional flows
- flows_per_min: flows / (capture_duration_s / 60)
- median_bytes_per_flow
- median_dur_s
- median_pkts_per_flow

Robustness
----------
- Uses capinfos to obtain capture duration and truncation warnings.
- Uses tshark field extraction; if a file is truncated/unreadable, it emits a CSV
  row with `error` set and continues (default behavior).

Requirements
------------
Wireshark CLI tools installed and available in PATH:
  - tshark
  - capinfos

Usage
-----
  python3 pcapng_flows_to_csv_and_table.py \
      --input-dir . \
      --recursive \
      --pattern "capturaAgente*.pcapng" \
      --out-csv flows_metrics.csv \
      --out-tex table_flow_structure_R5.tex

Then in LaTeX replace your flow table with:
  \\input{table_flow_structure_R5.tex}
"""

from __future__ import annotations

import argparse
import csv
import math
import os
import re
import subprocess
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


# -------------------------
# Filename parsing (optional metadata)
# -------------------------

FILENAME_RE = re.compile(
    r"^capturaAgente(?P<agent>[A-Za-z]+)(?P<dur>\d+m|1h)(?P<run>\d+)\.(?:pcapng|pcap)$"
)
DURATION_MAP_MIN = {"5m": 5, "15m": 15, "60m": 60, "1h": 60}


def parse_filename(p: Path) -> Dict[str, object]:
    m = FILENAME_RE.match(p.name)
    out = {
        "filename": p.name,
        "profile": None,
        "duration_label": None,
        "duration_requested_min": None,
        "run_idx": None,
    }
    if not m:
        return out

    agent = m.group("agent").lower()
    dur = m.group("dur")
    run_idx = int(m.group("run"))

    if agent.startswith("admin"):
        profile = "admin"
    elif agent.startswith("gamer"):
        profile = "gamer"
    elif agent.startswith("web") or agent.startswith("normal"):
        profile = "regular"
    else:
        profile = agent

    out.update(
        {
            "profile": profile,
            "duration_label": dur,
            "duration_requested_min": DURATION_MAP_MIN.get(dur),
            "run_idx": run_idx,
        }
    )
    return out


# -------------------------
# Subprocess helpers
# -------------------------

TRUNCATED_TSHARK_MSG = "cut short in the middle of a packet"
CAP_TRUNC_1 = "appears to have been cut short in the middle of a packet"
CAP_TRUNC_2 = "will continue anyway"

CAPINFOS_DURATION = re.compile(r"Capture duration:\s+([0-9.]+)")


def run_cmd(cmd: List[str]) -> Tuple[int, str, str]:
    env = os.environ.copy()
    env.setdefault("LC_ALL", "C")
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    return res.returncode, res.stdout, res.stderr


def capinfos_duration_and_trunc(pcap: Path) -> Tuple[Optional[float], int, str, Optional[str]]:
    """
    Returns (duration_seconds or None, truncated_flag 0/1, stderr_if_truncated, error_msg_if_any).
    """
    rc, out, err = run_cmd(["capinfos", str(pcap)])
    stderr = (err or "").strip()
    truncated = int((CAP_TRUNC_1 in stderr) and (CAP_TRUNC_2 in stderr))

    if rc != 0 and not truncated:
        return None, 0, "", f"capinfos_failed(exit={rc}): {stderr}"

    m = CAPINFOS_DURATION.search(out)
    dur = float(m.group(1)) if m else None
    return dur, truncated, (stderr if truncated else ""), None


# -------------------------
# Robust statistics (no pandas/numpy)
# -------------------------

def percentile(sorted_x: List[float], p: float) -> float:
    """Linear-interpolated percentile for a pre-sorted list."""
    if not sorted_x:
        return float("nan")
    if p <= 0:
        return float(sorted_x[0])
    if p >= 100:
        return float(sorted_x[-1])

    n = len(sorted_x)
    pos = (n - 1) * (p / 100.0)
    lo = int(math.floor(pos))
    hi = int(math.ceil(pos))
    if lo == hi:
        return float(sorted_x[lo])
    w = pos - lo
    return float(sorted_x[lo] * (1.0 - w) + sorted_x[hi] * w)


def median(x: List[float]) -> float:
    if not x:
        return float("nan")
    sx = sorted(x)
    n = len(sx)
    mid = n // 2
    if n % 2 == 1:
        return float(sx[mid])
    return float((sx[mid - 1] + sx[mid]) / 2.0)


def iqr(x: List[float]) -> float:
    if not x:
        return float("nan")
    sx = sorted(x)
    return percentile(sx, 75) - percentile(sx, 25)


def fmt_int_med_iqr(med: float, i: float) -> str:
    if math.isnan(med):
        return "--"
    med_s = str(int(round(med)))
    if math.isnan(i) or i == 0:
        return med_s
    return f"{med_s} [{int(round(i))}]"


def fmt_float_med_iqr(med: float, i: float, nd: int = 2) -> str:
    if math.isnan(med):
        return "--"
    med_s = f"{med:.{nd}f}"
    if math.isnan(i) or i == 0:
        return med_s
    return f"{med_s} [{i:.{nd}f}]"


# -------------------------
# Flow aggregation
# -------------------------

@dataclass
class FlowAgg:
    first_ts: float
    last_ts: float
    bytes_total: int
    pkts_total: int

    def update(self, ts: float, frame_len: int) -> None:
        if ts < self.first_ts:
            self.first_ts = ts
        if ts > self.last_ts:
            self.last_ts = ts
        self.bytes_total += frame_len
        self.pkts_total += 1

    @property
    def duration_s(self) -> float:
        d = self.last_ts - self.first_ts
        return float(d) if d > 0 else 0.0


def endpoint_tuple(ip: str, port: int) -> Tuple[str, int]:
    return (ip, int(port))


def bidir_flow_key(proto: str, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> Tuple[str, str, int, str, int]:
    a = endpoint_tuple(src_ip, src_port)
    b = endpoint_tuple(dst_ip, dst_port)
    if a <= b:
        (ip1, p1), (ip2, p2) = a, b
    else:
        (ip1, p1), (ip2, p2) = b, a
    return (proto, ip1, p1, ip2, p2)


def iter_packets_tshark(pcap: Path) -> Tuple[Optional[Iterable[List[str]]], Optional[str]]:
    """
    Stream packets from tshark as CSV rows.
    Returns (iterator, error_or_None).
    """
    # Fields: ts, ipv4/ipv6 src/dst, tcp ports, udp ports, proto (ip.proto or ipv6.nxt), frame.len
    cmd = [
        "tshark", "-n",
        "-r", str(pcap),
        "-T", "fields",
        "-E", "separator=,",
        "-E", "quote=d",
        "-e", "frame.time_epoch",
        "-e", "ip.src", "-e", "ip.dst",
        "-e", "ipv6.src", "-e", "ipv6.dst",
        "-e", "tcp.srcport", "-e", "tcp.dstport",
        "-e", "udp.srcport", "-e", "udp.dstport",
        "-e", "ip.proto", "-e", "ipv6.nxt",
        "-e", "frame.len",
    ]
    # Use Popen to stream
    env = os.environ.copy()
    env.setdefault("LC_ALL", "C")
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    except FileNotFoundError:
        return None, "tshark_not_found"

    assert p.stdout is not None
    assert p.stderr is not None

    # We will wrap stdout lines and later check stderr/return code at the end.
    def gen():
        reader = csv.reader(p.stdout)
        for row in reader:
            yield row
        # Wait and collect stderr
        rc = p.wait()
        err = p.stderr.read()
        stderr = (err or "").strip()
        if rc != 0:
            if TRUNCATED_TSHARK_MSG in stderr:
                raise RuntimeError("tshark_truncated(stream)")
            raise RuntimeError(f"tshark_failed(exit={rc}): {stderr}")

    return gen(), None


def safe_float(x: str) -> Optional[float]:
    try:
        return float(x)
    except Exception:
        return None


def safe_int(x: str) -> Optional[int]:
    try:
        return int(x)
    except Exception:
        return None


def compute_flow_metrics(pcap: Path) -> Tuple[Dict[str, object], List[str]]:
    """
    Returns (metrics_dict, errors_list).
    """
    errors: List[str] = []
    meta = parse_filename(pcap)

    dur_s, cap_truncated, cap_stderr, cap_err = capinfos_duration_and_trunc(pcap)
    if cap_err:
        errors.append(cap_err)

    flows: Dict[Tuple[str, str, int, str, int], FlowAgg] = {}

    it, it_err = iter_packets_tshark(pcap)
    if it_err:
        errors.append(it_err)
        # Return empty metrics row
        return {
            **meta,
            "capture_duration_s": dur_s,
            "capinfos_truncated": cap_truncated,
            "capinfos_stderr": cap_stderr,
            "flows": 0,
            "flows_per_min": None,
            "median_bytes_per_flow": None,
            "median_dur_s": None,
            "median_pkts_per_flow": None,
        }, errors

    assert it is not None

    try:
        for row in it:
            # Expected columns:
            # 0 ts, 1 ip.src, 2 ip.dst, 3 ipv6.src, 4 ipv6.dst,
            # 5 tcp.srcport, 6 tcp.dstport, 7 udp.srcport, 8 udp.dstport,
            # 9 ip.proto, 10 ipv6.nxt, 11 frame.len
            if len(row) < 12:
                continue

            ts = safe_float(row[0])
            if ts is None:
                continue

            src = row[1] or row[3]
            dst = row[2] or row[4]
            if not src or not dst:
                continue

            ip_proto = safe_int(row[9])  # IPv4
            ipv6_nxt = safe_int(row[10])  # IPv6 next header
            proto_num = ip_proto if ip_proto is not None else ipv6_nxt

            frame_len = safe_int(row[11])
            if frame_len is None:
                continue

            if proto_num == 6:  # TCP
                sp = safe_int(row[5])
                dp = safe_int(row[6])
                if sp is None or dp is None:
                    continue
                key = bidir_flow_key("tcp", src, sp, dst, dp)
            elif proto_num == 17:  # UDP
                sp = safe_int(row[7])
                dp = safe_int(row[8])
                if sp is None or dp is None:
                    continue
                key = bidir_flow_key("udp", src, sp, dst, dp)
            else:
                continue  # non-TCP/UDP ignored for 5-tuple flow table

            agg = flows.get(key)
            if agg is None:
                flows[key] = FlowAgg(first_ts=ts, last_ts=ts, bytes_total=frame_len, pkts_total=1)
            else:
                agg.update(ts, frame_len)

    except RuntimeError as e:
        msg = str(e)
        if "tshark_truncated" in msg:
            errors.append("tshark_truncated(flow_stream)")
        else:
            errors.append(f"tshark_stream_error: {msg}")

    # Compute per-capture indicators
    n_flows = len(flows)
    bytes_pf: List[float] = []
    dur_pf: List[float] = []
    pkts_pf: List[float] = []

    for fa in flows.values():
        bytes_pf.append(float(fa.bytes_total))
        dur_pf.append(float(fa.duration_s))
        pkts_pf.append(float(fa.pkts_total))

    med_bytes = median(bytes_pf)
    med_dur = median(dur_pf)
    med_pkts = median(pkts_pf)

    flows_per_min = None
    if dur_s and dur_s > 0:
        flows_per_min = n_flows / (dur_s / 60.0)

    return {
        **meta,
        "capture_duration_s": dur_s,
        "capinfos_truncated": cap_truncated,
        "capinfos_stderr": cap_stderr,
        "flows": n_flows,
        "flows_per_min": flows_per_min,
        "median_bytes_per_flow": med_bytes if not math.isnan(med_bytes) else None,
        "median_dur_s": med_dur if not math.isnan(med_dur) else None,
        "median_pkts_per_flow": med_pkts if not math.isnan(med_pkts) else None,
    }, errors


# -------------------------
# Aggregation and LaTeX output
# -------------------------

def write_csv(rows: List[Dict[str, object]], out_csv: Path) -> None:
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(rows[0].keys())
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)


def group_key(profile: str, dur_label: str) -> Tuple[str, str]:
    dur_disp = "60m" if dur_label == "1h" else dur_label
    return (profile, dur_disp)


def make_table(rows: List[Dict[str, object]]) -> str:
    # Keep only rows with parsed metadata and no truncation/errors
    ok = []
    for r in rows:
        if not r.get("profile") or not r.get("duration_label"):
            continue
        if int(r.get("capinfos_truncated") or 0) == 1:
            continue
        if (r.get("error") or "").strip():
            continue
        ok.append(r)

    grouped: Dict[Tuple[str, str], List[Dict[str, object]]] = defaultdict(list)
    for r in ok:
        grouped[group_key(str(r["profile"]), str(r["duration_label"]))].append(r)

    # Build LaTeX rows in preferred order
    prof_order = ["regular", "gamer", "admin"]
    dur_order = ["5m", "15m", "60m"]

    lines: List[str] = []
    lines.append(r"""\begin{table*}[t]
\centering
\small
\setlength{\tabcolsep}{4pt}
\renewcommand{\arraystretch}{1.15}
\resizebox{\textwidth}{!}{%
\begin{tabular}{llrrrrr}
\toprule
\textbf{Profile} & \textbf{Dur.} &
\textbf{Flows} & \textbf{Flows/min} &
\textbf{Median bytes/flow} & \textbf{Median dur. (s)} & \textbf{Median pkts/flow} \\
\midrule
""")

    def prof_label(p: str) -> str:
        return "Regular" if p == "regular" else ("Gamer" if p == "gamer" else "Administrator")

    for pi, p in enumerate(prof_order):
        for di, d in enumerate(dur_order):
            key = (p, d)
            runs = grouped.get(key, [])
            if not runs:
                # Still emit a placeholder row if missing
                lines.append(f"{prof_label(p)} & {d} & -- & -- & -- & -- & -- \\\\\n")
                continue

            flows_list = [float(r["flows"]) for r in runs if r.get("flows") is not None]
            fpm_list = [float(r["flows_per_min"]) for r in runs if r.get("flows_per_min") is not None]
            mb_list = [float(r["median_bytes_per_flow"]) for r in runs if r.get("median_bytes_per_flow") is not None]
            md_list = [float(r["median_dur_s"]) for r in runs if r.get("median_dur_s") is not None]
            mp_list = [float(r["median_pkts_per_flow"]) for r in runs if r.get("median_pkts_per_flow") is not None]

            flows_med, flows_i = median(flows_list), iqr(flows_list)
            fpm_med, fpm_i = median(fpm_list), iqr(fpm_list)
            mb_med, mb_i = median(mb_list), iqr(mb_list)
            md_med, md_i = median(md_list), iqr(md_list)
            mp_med, mp_i = median(mp_list), iqr(mp_list)

            lines.append(
                f"{prof_label(p)} & {d} & "
                f"{fmt_int_med_iqr(flows_med, flows_i)} & "
                f"{fmt_float_med_iqr(fpm_med, fpm_i, nd=2)} & "
                f"{fmt_int_med_iqr(mb_med, mb_i)} & "
                f"{fmt_float_med_iqr(md_med, md_i, nd=4)} & "
                f"{fmt_int_med_iqr(mp_med, mp_i)} \\\\\n"
            )

        if p != prof_order[-1]:
            lines.append(r"\midrule" + "\n")

    lines.append(r"""\bottomrule
\end{tabular}
}
\caption{Flow-level structure metrics by profile and duration. Values are reported as median~[IQR] over $R=5$ independent runs per condition. Flows are bidirectional TCP/UDP 5-tuples; non-TCP/UDP traffic is excluded from flow aggregation.}
\label{tab:flow_structure}
\end{table*}
""")
    return "".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input-dir", required=True)
    ap.add_argument("--pattern", default="capturaAgente*.pcapng")
    ap.add_argument("--recursive", action="store_true")
    ap.add_argument("--out-csv", default="flows_metrics.csv")
    ap.add_argument("--out-tex", default="table_flow_structure_R5.tex")
    ap.add_argument("--abort-on-error", action="store_true", help="Abort on first file-level error.")
    args = ap.parse_args()

    in_dir = Path(args.input_dir).expanduser().resolve()
    out_csv = Path(args.out_csv).expanduser().resolve()
    out_tex = Path(args.out_tex).expanduser().resolve()

    pcaps = sorted(in_dir.rglob(args.pattern)) if args.recursive else sorted(in_dir.glob(args.pattern))
    if not pcaps:
        raise SystemExit(f"No files matched: {in_dir}/{args.pattern}")

    rows: List[Dict[str, object]] = []
    for p in pcaps:
        print(f"[+] Processing {p.name}")
        metrics, errors = compute_flow_metrics(p)
        metrics["error"] = " | ".join(errors)
        metrics["path"] = str(p.resolve())
        if args.abort_on_error and metrics["error"]:
            raise SystemExit(f"Aborting on error for {p.name}: {metrics['error']}")
        rows.append(metrics)

    # Write per-capture CSV
    write_csv(rows, out_csv)
    print(f"[done] Wrote per-capture flow metrics: {out_csv}")

    # Write LaTeX table
    tex = make_table(rows)
    out_tex.write_text(tex, encoding="utf-8")
    print(f"[done] Wrote LaTeX table: {out_tex}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
