#!/usr/bin/env python3
"""
Extract host-level traffic metrics from 900-s PCAP/PCAPNG windows.

Input:
    CSV manifest with columns:
    pcap,source,dataset,profile,host,local_ip,nominal_duration_s,include

Output:
    One CSV row per included window.

Requirements:
    - Python 3.9+
    - tshark available in PATH
    - numpy

Example:
    python3 extract_window_metrics.py \
        --manifest windows_manifest.csv \
        --output results/per_window/cicids2017_win10_14.csv
"""

from __future__ import annotations

import argparse
import csv
import math
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Optional, Tuple

import numpy as np


@dataclass
class FlowStats:
    first_ts: float
    last_ts: float
    packets: int = 0
    bytes: int = 0


FlowKey = Tuple[str, str, int, int]


OUTPUT_FIELDS = [
    "source",
    "dataset",
    "profile",
    "host",
    "local_ip",
    "window",
    "pcap",
    "nominal_duration_s",
    "observed_duration_s",
    "packet_count",
    "flow_count",
    "flows_per_min",
    "packets_per_min",
    "tcp_share_pct",
    "udp_share_pct",
    "dns_share_pct",
    "https_share_pct",
    "flow_duration_median_s",
    "packets_per_flow_median",
    "bytes_per_flow_median",
    "packet_size_median_bytes",
    "packet_size_p95_bytes",
    "iat_median_ms",
    "iat_p95_ms",
    "destination_entropy_bits",
    "port_entropy_bits",
    "out_of_order_packets",
]


def parse_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "y"}


def safe_int(value: str) -> Optional[int]:
    value = value.strip()
    if not value:
        return None
    try:
        # tshark can occasionally emit comma-separated values for repeated fields.
        return int(value.split(",")[0])
    except ValueError:
        return None


def safe_float(value: str) -> Optional[float]:
    value = value.strip()
    if not value:
        return None
    try:
        return float(value.split(",")[0])
    except ValueError:
        return None


def entropy_bits(counts: Iterable[int]) -> float:
    counts_array = np.asarray(list(counts), dtype=np.float64)
    total = counts_array.sum()
    if total <= 0:
        return float("nan")
    probabilities = counts_array / total
    return float(-(probabilities * np.log2(probabilities)).sum())


def percentile(values: Iterable[float], q: float) -> float:
    array = np.asarray(list(values), dtype=np.float64)
    if array.size == 0:
        return float("nan")
    return float(np.percentile(array, q))


def median(values: Iterable[float]) -> float:
    array = np.asarray(list(values), dtype=np.float64)
    if array.size == 0:
        return float("nan")
    return float(np.median(array))


def tshark_rows(pcap: Path):
    """
    Stream relevant packet fields from tshark.

    Field order:
      frame.time_epoch
      frame.len
      ip.src
      ip.dst
      ipv6.src
      ipv6.dst
      ip.proto
      ipv6.nxt
      tcp.srcport
      tcp.dstport
      udp.srcport
      udp.dstport
    """
    command = [
        "tshark",
        "-n",
        "-r",
        str(pcap),
        "-Y",
        "ip || ipv6",
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-E",
        "quote=n",
        "-E",
        "occurrence=f",
        "-e",
        "frame.time_epoch",
        "-e",
        "frame.len",
        "-e",
        "ip.src",
        "-e",
        "ip.dst",
        "-e",
        "ipv6.src",
        "-e",
        "ipv6.dst",
        "-e",
        "ip.proto",
        "-e",
        "ipv6.nxt",
        "-e",
        "tcp.srcport",
        "-e",
        "tcp.dstport",
        "-e",
        "udp.srcport",
        "-e",
        "udp.dstport",
    ]

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1024 * 1024,
    )

    assert process.stdout is not None
    for line_number, line in enumerate(process.stdout, start=1):
        fields = line.rstrip("\n").split("\t")
        if len(fields) < 12:
            fields.extend([""] * (12 - len(fields)))
        yield line_number, fields[:12]

    stderr = process.stderr.read() if process.stderr is not None else ""
    return_code = process.wait()
    if return_code != 0:
        raise RuntimeError(
            f"tshark failed for {pcap} with exit code {return_code}:\n{stderr}"
        )


def protocol_name(ip_proto: Optional[int]) -> str:
    if ip_proto == 6:
        return "TCP"
    if ip_proto == 17:
        return "UDP"
    if ip_proto == 1:
        return "ICMP"
    if ip_proto == 58:
        return "ICMPv6"
    return f"IP_{ip_proto}" if ip_proto is not None else "IP_UNKNOWN"


def extract_metrics(record: dict) -> dict:
    pcap = Path(record["pcap"]).expanduser()
    if not pcap.exists():
        raise FileNotFoundError(f"PCAP not found: {pcap}")

    local_ip = record["local_ip"].strip()
    nominal_duration_s = float(record.get("nominal_duration_s", "900") or 900)

    flows: Dict[FlowKey, FlowStats] = {}
    packet_sizes = []
    timestamps = []

    first_ts: Optional[float] = None
    last_ts: Optional[float] = None
    out_of_order_packets = 0
    previous_ts: Optional[float] = None

    for line_number, fields in tshark_rows(pcap):
        (
            ts_s,
            frame_len_s,
            ipv4_src,
            ipv4_dst,
            ipv6_src,
            ipv6_dst,
            ipv4_proto_s,
            ipv6_next_s,
            tcp_src_s,
            tcp_dst_s,
            udp_src_s,
            udp_dst_s,
        ) = fields

        ts = safe_float(ts_s)
        frame_len = safe_int(frame_len_s)
        if ts is None or frame_len is None:
            continue

        src_ip = ipv4_src or ipv6_src
        dst_ip = ipv4_dst or ipv6_dst
        if not src_ip or not dst_ip:
            continue

        if src_ip == local_ip:
            remote_ip = dst_ip
            outbound = True
        elif dst_ip == local_ip:
            remote_ip = src_ip
            outbound = False
        else:
            # Defensive check: manifest IP does not belong to this packet.
            continue

        proto_number = safe_int(ipv4_proto_s)
        if proto_number is None:
            proto_number = safe_int(ipv6_next_s)
        proto = protocol_name(proto_number)

        tcp_src = safe_int(tcp_src_s)
        tcp_dst = safe_int(tcp_dst_s)
        udp_src = safe_int(udp_src_s)
        udp_dst = safe_int(udp_dst_s)

        if proto == "TCP":
            src_port, dst_port = tcp_src, tcp_dst
        elif proto == "UDP":
            src_port, dst_port = udp_src, udp_dst
        else:
            src_port, dst_port = None, None

        if outbound:
            local_port = src_port or 0
            remote_port = dst_port or 0
        else:
            local_port = dst_port or 0
            remote_port = src_port or 0

        # Host-relative bidirectional key. Reverse-direction packets map
        # to the same tuple because local and remote endpoints are fixed.
        flow_key: FlowKey = (proto, remote_ip, local_port, remote_port)

        stats = flows.get(flow_key)
        if stats is None:
            stats = FlowStats(first_ts=ts, last_ts=ts)
            flows[flow_key] = stats

        stats.last_ts = max(stats.last_ts, ts)
        stats.first_ts = min(stats.first_ts, ts)
        stats.packets += 1
        stats.bytes += frame_len

        packet_sizes.append(frame_len)
        timestamps.append(ts)

        if previous_ts is not None and ts < previous_ts:
            out_of_order_packets += 1
        previous_ts = ts

        first_ts = ts if first_ts is None else min(first_ts, ts)
        last_ts = ts if last_ts is None else max(last_ts, ts)

    packet_count = len(packet_sizes)
    flow_count = len(flows)

    if packet_count == 0 or flow_count == 0:
        raise RuntimeError(f"No usable host IP traffic found in {pcap}")

    flow_values = list(flows.items())
    flow_durations = [s.last_ts - s.first_ts for _, s in flow_values]
    packets_per_flow = [s.packets for _, s in flow_values]
    bytes_per_flow = [s.bytes for _, s in flow_values]

    tcp_count = sum(1 for key, _ in flow_values if key[0] == "TCP")
    udp_count = sum(1 for key, _ in flow_values if key[0] == "UDP")
    dns_count = sum(
        1 for key, _ in flow_values if key[2] == 53 or key[3] == 53
    )
    https_count = sum(
        1
        for key, _ in flow_values
        if key[0] in {"TCP", "UDP"} and (key[2] == 443 or key[3] == 443)
    )

    destination_counts = Counter(key[1] for key, _ in flow_values)

    # Remote-port entropy is defined over TCP/UDP flows with a valid remote port.
    remote_port_counts = Counter(
        key[3]
        for key, _ in flow_values
        if key[0] in {"TCP", "UDP"} and key[3] > 0
    )

    timestamp_array = np.asarray(timestamps, dtype=np.float64)
    if out_of_order_packets:
        timestamp_array.sort()
    iats_ms = np.diff(timestamp_array) * 1000.0

    observed_duration_s = (
        float(last_ts - first_ts)
        if first_ts is not None and last_ts is not None
        else float("nan")
    )
    nominal_minutes = nominal_duration_s / 60.0

    return {
        "source": record.get("source", ""),
        "dataset": record.get("dataset", ""),
        "profile": record.get("profile", ""),
        "host": record.get("host", ""),
        "local_ip": local_ip,
        "window": pcap.name,
        "pcap": str(pcap),
        "nominal_duration_s": nominal_duration_s,
        "observed_duration_s": observed_duration_s,
        "packet_count": packet_count,
        "flow_count": flow_count,
        "flows_per_min": flow_count / nominal_minutes,
        "packets_per_min": packet_count / nominal_minutes,
        "tcp_share_pct": 100.0 * tcp_count / flow_count,
        "udp_share_pct": 100.0 * udp_count / flow_count,
        "dns_share_pct": 100.0 * dns_count / flow_count,
        "https_share_pct": 100.0 * https_count / flow_count,
        "flow_duration_median_s": median(flow_durations),
        "packets_per_flow_median": median(packets_per_flow),
        "bytes_per_flow_median": median(bytes_per_flow),
        "packet_size_median_bytes": median(packet_sizes),
        "packet_size_p95_bytes": percentile(packet_sizes, 95),
        "iat_median_ms": median(iats_ms),
        "iat_p95_ms": percentile(iats_ms, 95),
        "destination_entropy_bits": entropy_bits(destination_counts.values()),
        "port_entropy_bits": entropy_bits(remote_port_counts.values()),
        "out_of_order_packets": out_of_order_packets,
    }


def write_row(writer: csv.DictWriter, row: dict) -> None:
    formatted = {}
    for key in OUTPUT_FIELDS:
        value = row.get(key, "")
        if isinstance(value, float):
            if math.isnan(value):
                formatted[key] = ""
            else:
                formatted[key] = f"{value:.10g}"
        else:
            formatted[key] = value
    writer.writerow(formatted)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Process at most N included windows (useful for validation).",
    )
    args = parser.parse_args()

    if not args.manifest.exists():
        print(f"Manifest not found: {args.manifest}", file=sys.stderr)
        return 2

    args.output.parent.mkdir(parents=True, exist_ok=True)

    with args.manifest.open(newline="", encoding="utf-8-sig") as manifest_file:
        records = list(csv.DictReader(manifest_file))

    required = {
        "pcap",
        "source",
        "dataset",
        "profile",
        "host",
        "local_ip",
        "nominal_duration_s",
        "include",
    }
    missing = required - set(records[0].keys() if records else [])
    if missing:
        print(
            f"Manifest is missing required columns: {', '.join(sorted(missing))}",
            file=sys.stderr,
        )
        return 2

    included_records = [r for r in records if parse_bool(r["include"])]
    if args.limit is not None:
        included_records = included_records[: args.limit]

    if not included_records:
        print("No included manifest rows found.", file=sys.stderr)
        return 2

    file_exists = args.output.exists()
    processed_windows = set()

    if file_exists:
        with args.output.open(newline="", encoding="utf-8") as existing:
            for row in csv.DictReader(existing):
                processed_windows.add(row.get("pcap", ""))

    mode = "a" if file_exists else "w"
    with args.output.open(mode, newline="", encoding="utf-8") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=OUTPUT_FIELDS)
        if not file_exists:
            writer.writeheader()

        total = len(included_records)
        for index, record in enumerate(included_records, start=1):
            pcap_text = str(Path(record["pcap"]).expanduser())
            if pcap_text in processed_windows:
                print(f"[{index}/{total}] SKIP already processed: {pcap_text}")
                continue

            print(f"[{index}/{total}] Processing: {pcap_text}", flush=True)
            try:
                result = extract_metrics(record)
            except Exception as exc:
                print(f"ERROR processing {pcap_text}: {exc}", file=sys.stderr)
                return 1

            write_row(writer, result)
            output_file.flush()
            print(
                f"    packets={result['packet_count']:,} "
                f"flows={result['flow_count']:,} "
                f"flows/min={result['flows_per_min']:.2f}",
                flush=True,
            )

    print(f"Results written to: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
