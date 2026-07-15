#!/usr/bin/env python3
"""
Summarize per-window metric CSVs as median [Q1-Q3].

Example:
    python3 summarize_window_metrics.py \
        --input results/per_window/cicids2017_win10_14.csv \
        --output results/summary/cicids2017_win10_14_summary.csv
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd


METRICS = [
    ("flows_per_min", "Flows per minute", "flows/min"),
    ("packets_per_min", "Packets per minute", "packets/min"),
    ("packets_per_flow_median", "Packets per flow", "packets"),
    ("bytes_per_flow_median", "Bytes per flow", "bytes"),
    ("flow_duration_median_s", "Flow duration", "s"),
    ("tcp_share_pct", "TCP flow share", "%"),
    ("udp_share_pct", "UDP flow share", "%"),
    ("dns_share_pct", "DNS flow share", "%"),
    ("https_share_pct", "Port-443 flow share", "%"),
    ("packet_size_median_bytes", "Packet size", "bytes"),
    ("packet_size_p95_bytes", "Packet-size p95", "bytes"),
    ("iat_median_ms", "Inter-arrival time", "ms"),
    ("iat_p95_ms", "Inter-arrival-time p95", "ms"),
    ("destination_entropy_bits", "Destination entropy", "bits"),
    ("port_entropy_bits", "Remote-port entropy", "bits"),
]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    df = pd.read_csv(args.input)
    rows = []

    for column, label, unit in METRICS:
        values = pd.to_numeric(df[column], errors="coerce").dropna().to_numpy()
        if len(values) == 0:
            continue
        q1, median, q3 = np.percentile(values, [25, 50, 75])
        rows.append(
            {
                "metric": label,
                "column": column,
                "n_windows": len(values),
                "median": median,
                "q1": q1,
                "q3": q3,
                "iqr": q3 - q1,
                "formatted": f"{median:.3f} [{q1:.3f}-{q3:.3f}]",
                "unit": unit,
            }
        )

    output = pd.DataFrame(rows)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    output.to_csv(args.output, index=False)

    print(output[["metric", "n_windows", "formatted", "unit"]].to_string(index=False))
    print(f"\nSummary written to: {args.output}")


if __name__ == "__main__":
    main()
