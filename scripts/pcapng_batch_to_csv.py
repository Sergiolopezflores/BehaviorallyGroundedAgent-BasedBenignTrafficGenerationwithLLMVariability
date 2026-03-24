#!/usr/bin/env python3
"""
pcapng_batch_to_csv_robust.py

Batch-extract per-capture summary metrics from .pcapng files into a single CSV.

Design goals
------------
- Robust on macOS (and other OSes) where `capinfos` may format numbers with separators
  or where some captures may be truncated.
- Never abort the batch by default: for any file that cannot be processed fully,
  emit a CSV row with `error` populated (Option B behavior).
- Produce totals (`packets_total`, `bytes_total`) from tshark, not capinfos.

Tools
-----
Requires Wireshark CLI tools:
  - tshark
  - capinfos

Usage
-----
  python3 pcapng_batch_to_csv_robust.py \
      --input-dir . \
      --pattern "capturaAgente*.pcapng" \
      --output captures_summary.csv

Optional:
  --recursive            search recursively under input-dir
  --abort-on-error       stop on first file-level error (default: keep going)
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import subprocess
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# -------------------------
# Filename parsing (optional metadata)
# -------------------------

FILENAME_RE = re.compile(
    r"^capturaAgente(?P<agent>[A-Za-z]+)(?P<dur>\d+m|1h)(?P<run>\d+)\.pcapng$"
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


def run_cmd(cmd: List[str]) -> Tuple[int, str, str]:
    env = os.environ.copy()
    # Reduce locale variability in tool output.
    env.setdefault("LC_ALL", "C")
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    return res.returncode, res.stdout, res.stderr


def _parse_int_token(token: str) -> int:
    """
    Parse an integer from a token that may include commas/spaces/units.
    Strips all non-digits.
    """
    digits = re.sub(r"\D", "", token)
    return int(digits) if digits else 0


# -------------------------
# capinfos: duration + truncation warning
# -------------------------

CAPINFOS_DURATION = re.compile(r"Capture duration:\s+([0-9.]+)")
CAP_TRUNC_1 = "appears to have been cut short in the middle of a packet"
CAP_TRUNC_2 = "will continue anyway"


def capinfos_duration_and_trunc(pcap: Path) -> Tuple[Optional[float], int, str, Optional[str]]:
    """
    Returns (duration_seconds or None, truncated_flag 0/1, stderr_if_truncated, error_msg_if_any).

    capinfos may return exit code 1 for truncated captures but still provides output.
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
# tshark metrics (safe wrappers)
# -------------------------

def tshark_pkt_count_safe(pcap: Path, display_filter: str) -> Tuple[int, Optional[str]]:
    """
    Count packets matching a display filter.

    Returns (count, error_message_or_None). Never raises.
    """
    cmd = ["tshark", "-r", str(pcap), "-Y", display_filter, "-T", "fields", "-e", "frame.number"]
    rc, out, err = run_cmd(cmd)
    if rc != 0:
        stderr = (err or "").strip()
        # Truncated file: treat as error but do not abort.
        if TRUNCATED_TSHARK_MSG in stderr:
            return 0, f"tshark_truncated({display_filter})"
        return 0, f"tshark_count_failed({display_filter}, exit={rc}): {stderr}"
    s = out.strip()
    return (0 if not s else s.count("\n") + 1), None


def tshark_peak_mbps_1s_safe(pcap: Path) -> Tuple[Optional[float], Optional[str]]:
    """
    Peak throughput (Mbps) using 1-second io,stat buckets.

    Returns (peak_mbps or None, error_message_or_None). Never raises.
    """
    rc, out, err = run_cmd(["tshark", "-r", str(pcap), "-q", "-z", "io,stat,1"])
    if rc != 0:
        stderr = (err or "").strip()
        if TRUNCATED_TSHARK_MSG in stderr:
            return None, "tshark_truncated(io,stat,1)"
        return None, f"tshark_io_stat_1_failed(exit={rc}): {stderr}"

    peak_bytes_per_s = 0
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cols = [c.strip() for c in line.strip("|").split("|")]
        if len(cols) < 3:
            continue
        b = _parse_int_token(cols[-1])
        if b > peak_bytes_per_s:
            peak_bytes_per_s = b

    return ((peak_bytes_per_s * 8.0) / 1e6 if peak_bytes_per_s > 0 else None), None


def tshark_totals_io_stat_safe(pcap: Path) -> Tuple[Optional[int], Optional[int], Optional[str]]:
    """
    Attempt totals from `tshark -z io,stat,0`.

    Returns (frames, bytes, error_message_or_None). Never raises.
    """
    rc, out, err = run_cmd(["tshark", "-r", str(pcap), "-q", "-z", "io,stat,0"])
    if rc != 0:
        stderr = (err or "").strip()
        if TRUNCATED_TSHARK_MSG in stderr:
            return None, None, "tshark_truncated(io,stat,0)"
        return None, None, f"tshark_io_stat_0_failed(exit={rc}): {stderr}"

    best_frames: Optional[int] = None
    best_bytes: Optional[int] = None

    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cols = [c.strip() for c in line.strip("|").split("|")]
        ints: List[int] = []
        for c in cols:
            v = _parse_int_token(c)
            if v:
                ints.append(v)
        if len(ints) >= 2:
            frames, bytes_ = ints[-2], ints[-1]
            if best_frames is None or frames > best_frames:
                best_frames, best_bytes = frames, bytes_

    if best_frames is None or best_bytes is None:
        return None, None, "tshark_io_stat_0_parse_failed"
    return best_frames, best_bytes, None


def tshark_sum_frame_len_safe(pcap: Path) -> Tuple[Optional[int], Optional[int], Optional[str]]:
    """
    Fallback totals: count frames and sum frame.len for all packets.

    Returns (frames, bytes, error_message_or_None). Never raises.
    """
    rc, out, err = run_cmd(["tshark", "-r", str(pcap), "-T", "fields", "-e", "frame.len"])
    if rc != 0:
        stderr = (err or "").strip()
        if TRUNCATED_TSHARK_MSG in stderr:
            return None, None, "tshark_truncated(frame.len)"
        return None, None, f"tshark_frame_len_failed(exit={rc}): {stderr}"

    frames = 0
    total_bytes = 0
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            total_bytes += int(line)
            frames += 1
        except ValueError:
            continue

    if frames <= 0:
        return None, None, "tshark_frame_len_parse_failed"
    return frames, total_bytes, None


def tshark_top_dport_safe(pcap: Path, proto: str) -> Tuple[Optional[int], int, Optional[str]]:
    """
    Return (top_port, top_count, error_message_or_None). Never raises.
    """
    proto = proto.lower()
    if proto not in ("tcp", "udp"):
        return None, 0, "invalid_proto"

    field = f"{proto}.dstport"
    rc, out, err = run_cmd(["tshark", "-r", str(pcap), "-Y", proto, "-T", "fields", "-e", field])
    if rc != 0:
        stderr = (err or "").strip()
        if TRUNCATED_TSHARK_MSG in stderr:
            return None, 0, f"tshark_truncated({proto}.dstport)"
        return None, 0, f"tshark_ports_failed({proto}, exit={rc}): {stderr}"

    ports: List[int] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ports.append(int(line))
        except ValueError:
            continue

    if not ports:
        return None, 0, None
    c = Counter(ports)
    top_port, top_cnt = c.most_common(1)[0]
    return top_port, int(top_cnt), None


# -------------------------
# Row builder
# -------------------------

def build_row(pcap: Path) -> Dict[str, object]:
    meta = parse_filename(pcap)
    errors: List[str] = []

    # capinfos (duration + truncated flag) is non-fatal
    dur_s, cap_truncated, cap_stderr, cap_err = capinfos_duration_and_trunc(pcap)
    if cap_err:
        errors.append(cap_err)

    # Protocol counts
    tcp_pkts, e = tshark_pkt_count_safe(pcap, "tcp")
    if e: errors.append(e)
    udp_pkts, e = tshark_pkt_count_safe(pcap, "udp")
    if e: errors.append(e)
    icmp_pkts, e = tshark_pkt_count_safe(pcap, "icmp")
    if e: errors.append(e)
    other_pkts, e = tshark_pkt_count_safe(pcap, "not (tcp or udp or icmp)")
    if e: errors.append(e)

    # Totals (frames/bytes): io,stat first, then frame.len fallback
    totals_source = "tshark_io_stat"
    frames_total, bytes_total, e = tshark_totals_io_stat_safe(pcap)
    if e:
        errors.append(e)
    if frames_total is None or bytes_total is None:
        totals_source = "tshark_frame_len"
        frames_total, bytes_total, e2 = tshark_sum_frame_len_safe(pcap)
        if e2:
            errors.append(e2)
        if frames_total is None or bytes_total is None:
            totals_source = "error"
            frames_total, bytes_total = 0, 0

    packets_total = int(frames_total or 0)
    bytes_total_i = int(bytes_total or 0)

    # Internal consistency flag
    sum_proto = tcp_pkts + udp_pkts + icmp_pkts + other_pkts
    totals_consistent = int(packets_total == sum_proto) if packets_total > 0 else 0

    # QUIC-like indicator
    udp443_pkts, e = tshark_pkt_count_safe(pcap, "udp.dstport == 443")
    if e: errors.append(e)
    tcp443_pkts, e = tshark_pkt_count_safe(pcap, "tcp.dstport == 443")
    if e: errors.append(e)

    # Peak throughput
    peak_mbps, e = tshark_peak_mbps_1s_safe(pcap)
    if e: errors.append(e)

    # Mean throughput
    mean_bps = (bytes_total_i * 8.0 / dur_s) if (dur_s and dur_s > 0 and bytes_total_i > 0) else None

    # Top ports
    top_udp_dport, top_udp_cnt, e = tshark_top_dport_safe(pcap, "udp")
    if e: errors.append(e)
    top_tcp_dport, top_tcp_cnt, e = tshark_top_dport_safe(pcap, "tcp")
    if e: errors.append(e)

    return {
        "filename": meta["filename"],
        "profile": meta["profile"],
        "duration_label": meta["duration_label"],
        "duration_requested_min": meta["duration_requested_min"],
        "run_idx": meta["run_idx"],
        "capture_duration_s": dur_s,
        "packets_total": packets_total,
        "bytes_total": bytes_total_i,
        "mean_bps": mean_bps,
        "peak_mbps_1s": peak_mbps,
        "tcp_pkts": tcp_pkts,
        "udp_pkts": udp_pkts,
        "icmp_pkts": icmp_pkts,
        "other_pkts": other_pkts,
        "udp443_pkts": udp443_pkts,
        "tcp443_pkts": tcp443_pkts,
        "top_udp_dport": top_udp_dport,
        "top_udp_dport_pkts": top_udp_cnt,
        "top_tcp_dport": top_tcp_dport,
        "top_tcp_dport_pkts": top_tcp_cnt,
        "capinfos_truncated": cap_truncated,
        "capinfos_stderr": cap_stderr,
        "totals_source": totals_source,
        "totals_consistent": totals_consistent,
        "error": " | ".join(errors),
        "path": str(pcap.resolve()),
    }


# -------------------------
# Main
# -------------------------

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input-dir", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--pattern", default="capturaAgente*.pcapng")
    ap.add_argument("--recursive", action="store_true", help="Search recursively under input-dir.")
    ap.add_argument("--abort-on-error", action="store_true", help="Abort on first file-level error.")
    args = ap.parse_args()

    in_dir = Path(args.input_dir).expanduser().resolve()
    out_csv = Path(args.output).expanduser().resolve()

    pcaps = sorted(in_dir.rglob(args.pattern)) if args.recursive else sorted(in_dir.glob(args.pattern))
    if not pcaps:
        raise SystemExit(f"No files matched: {in_dir}/{args.pattern}")

    rows: List[Dict[str, object]] = []
    for p in pcaps:
        print(f"[+] Processing {p.name}")
        row = build_row(p)
        if args.abort_on_error and row.get("error"):
            raise SystemExit(f"Aborting on error for {p.name}: {row['error']}")
        rows.append(row)

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(rows[0].keys())
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)

    print(f"[done] Wrote {len(rows)} rows to {out_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
