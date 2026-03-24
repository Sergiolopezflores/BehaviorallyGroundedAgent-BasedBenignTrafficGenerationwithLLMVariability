#!/usr/bin/env python3
"""
sanity_iforest.py

Sanity check for "benign outliers under homogeneous baselines" using an
unsupervised anomaly detector over per-run summary features.

Inputs
------
- captures_summary.csv  : per-capture packet-level summaries (bytes, packets, protocol counts, etc.)
- flows_metrics.csv     : per-capture flow-structure summaries (flows/min, median bytes/flow, etc.)

Method
------
1) Merge both CSVs on `filename`.
2) Filter to a selected duration (default: 15m) and to valid captures (error=="" and capinfos_truncated==0).
3) Build a feature vector per run:
   - log1p(bytes_total, packets_total, mean_bps, peak_mbps_1s)
   - packet-share features: tcp_pct, udp_pct (excluding UDP/443), udp443_pct, icmp_pct
   - flow features: log1p(flows_per_min), log1p(median_bytes_per_flow), log1p(median_dur_s), log1p(median_pkts_per_flow)
4) Train IsolationForest on a baseline set and compute the fraction of runs flagged as anomalies in each profile.

Two baselines are reported:
A) Regular-only baseline (train on regular-user runs)
B) Mixed baseline (train on regular+gamer+admin runs)

Thresholding
------------
Default is conservative: threshold = min training score (no training runs are flagged).
Optionally you can use a training-score quantile threshold.

Outputs
-------
- Prints a small report to stdout
- Optionally writes a LaTeX table with the flagged fractions.

Requirements
------------
pip install pandas scikit-learn

Example
-------
python3 sanity_iforest.py \
  --captures captures_summary.csv \
  --flows flows_metrics.csv \
  --duration 15m \
  --out-tex table_sanity_iforest.tex
"""

from __future__ import annotations

import argparse
import math
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler


def build_features(df: pd.DataFrame) -> Tuple[pd.DataFrame, List[str]]:
    d = df.copy()

    # Ensure numeric
    num_cols = [
        "bytes_total", "packets_total", "mean_bps", "peak_mbps_1s",
        "tcp_pkts", "udp_pkts", "icmp_pkts", "other_pkts", "udp443_pkts",
        "flows", "flows_per_min", "median_bytes_per_flow", "median_dur_s", "median_pkts_per_flow",
    ]
    for c in num_cols:
        if c in d.columns:
            d[c] = pd.to_numeric(d[c], errors="coerce")

    # UDP share excluding UDP/443 (to match paper convention)
    d["udp_non443_pkts"] = (d["udp_pkts"] - d["udp443_pkts"]).clip(lower=0)

    # Recompute packet totals from components for consistent shares
    d["pkts_total_recalc"] = (
        d["tcp_pkts"] + d["udp_non443_pkts"] + d["udp443_pkts"] + d["icmp_pkts"] + d["other_pkts"]
    ).astype(float)

    # Shares (avoid division by zero)
    eps = 1e-12
    denom = d["pkts_total_recalc"].clip(lower=eps)
    d["tcp_pct"] = d["tcp_pkts"] / denom
    d["udp_pct"] = d["udp_non443_pkts"] / denom
    d["udp443_pct"] = d["udp443_pkts"] / denom
    d["icmp_pct"] = d["icmp_pkts"] / denom

    # Log transforms for heavy-tailed magnitudes
    d["log_bytes"] = np.log1p(d["bytes_total"])
    d["log_pkts"] = np.log1p(d["packets_total"])
    d["log_mean_bps"] = np.log1p(d["mean_bps"])
    d["log_peak_mbps"] = np.log1p(d["peak_mbps_1s"])

    d["log_flows_per_min"] = np.log1p(d["flows_per_min"])
    d["log_med_bytes_flow"] = np.log1p(d["median_bytes_per_flow"])
    d["log_med_dur"] = np.log1p(d["median_dur_s"])
    d["log_med_pkts_flow"] = np.log1p(d["median_pkts_per_flow"])

    feat_cols = [
        "log_bytes", "log_pkts", "log_mean_bps", "log_peak_mbps",
        "tcp_pct", "udp_pct", "udp443_pct", "icmp_pct",
        "log_flows_per_min", "log_med_bytes_flow", "log_med_dur", "log_med_pkts_flow",
    ]
    # Sanity: drop rows with missing features
    d = d.dropna(subset=feat_cols)
    return d, feat_cols


def fit_model(X_train: np.ndarray, seed: int, n_estimators: int) -> Tuple[RobustScaler, IsolationForest, np.ndarray]:
    scaler = RobustScaler(with_centering=True, with_scaling=True)
    Xs = scaler.fit_transform(X_train)

    clf = IsolationForest(
        n_estimators=n_estimators,
        random_state=seed,
        n_jobs=-1,
    )
    clf.fit(Xs)
    scores = clf.score_samples(Xs)  # higher is more normal
    return scaler, clf, scores


def threshold_from_train(scores: np.ndarray, mode: str, q: float) -> float:
    if mode == "min_train":
        return float(scores.min() - 1e-12)
    if mode == "quantile":
        return float(np.quantile(scores, q))
    raise ValueError(f"Unknown threshold mode: {mode}")


def flagged_rate(scaler: RobustScaler, clf: IsolationForest, thr: float, X: np.ndarray) -> float:
    Xs = scaler.transform(X)
    scores = clf.score_samples(Xs)
    flagged = scores < thr
    return float(flagged.mean())


def fmt_pct(x: float) -> str:
    return f"{100.0 * x:.1f}"


def make_latex_table(duration_label: str, reg_only: Dict[str, float], mixed: Dict[str, float]) -> str:
    # Only report gamer/admin flagged fractions, as in the suggested paper table.
    return rf"""\begin{{table}}[t]
\centering
\small
\setlength{{\tabcolsep}}{{5pt}}
\renewcommand{{\arraystretch}}{{1.12}}
\begin{{tabular}}{{lcc}}
\toprule
\textbf{{Training baseline ({duration_label})}} & \textbf{{Gamer flagged (\%)}} & \textbf{{Admin flagged (\%)}} \\
\midrule
Regular only & {fmt_pct(reg_only['gamer'])} & {fmt_pct(reg_only['admin'])} \\
Mixed profiles & {fmt_pct(mixed['gamer'])} & {fmt_pct(mixed['admin'])} \\
\bottomrule
\end{{tabular}}
\caption{{Sanity check with an unsupervised anomaly detector (Isolation Forest) over per-run summary features. Values report the fraction of benign runs flagged as anomalous under the specified training baseline.}}
\label{{tab:sanity_iforest}}
\end{{table}}
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--captures", required=True, help="Path to captures_summary.csv")
    ap.add_argument("--flows", required=True, help="Path to flows_metrics.csv")
    ap.add_argument("--duration", default="15m", help="Duration label to analyze (e.g., 5m, 15m, 60m or 1h)")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--n-estimators", type=int, default=500)
    ap.add_argument("--threshold", choices=["min_train", "quantile"], default="min_train")
    ap.add_argument("--q", type=float, default=0.05, help="Training-score quantile if --threshold=quantile")
    ap.add_argument("--out-tex", default=None, help="Optional LaTeX output path")
    args = ap.parse_args()

    cap = pd.read_csv(Path(args.captures))
    flo = pd.read_csv(Path(args.flows))

    # Normalize labels: treat 1h as 60m for grouping if needed
    cap["duration_label"] = cap["duration_label"].replace({"1h": "60m"})
    flo["duration_label"] = flo["duration_label"].replace({"1h": "60m"})
    duration = "60m" if args.duration == "1h" else args.duration

    # Filter valid rows (robust scripts already add these columns)
    for df in (cap, flo):
        if "error" in df.columns:
            df["error"] = df["error"].fillna("").astype(str)
        if "capinfos_truncated" in df.columns:
            df["capinfos_truncated"] = pd.to_numeric(df["capinfos_truncated"], errors="coerce").fillna(0).astype(int)

    cap_ok = cap[
        (cap["profile"].notna()) &
        (cap["duration_label"] == duration) &
        ((cap.get("error", "") == "") | (cap.get("error", "") == "")) &
        (cap.get("capinfos_truncated", 0) == 0)
    ].copy()

    flo_ok = flo[
        (flo["profile"].notna()) &
        (flo["duration_label"] == duration) &
        ((flo.get("error", "") == "") | (flo.get("error", "") == "")) &
        (flo.get("capinfos_truncated", 0) == 0)
    ].copy()

    df = cap_ok.merge(
        flo_ok[[
            "filename", "flows", "flows_per_min",
            "median_bytes_per_flow", "median_dur_s", "median_pkts_per_flow"
        ]],
        on="filename",
        how="inner"
    )

    df, feat_cols = build_features(df)

    # Split
    profiles = ["regular", "gamer", "admin"]
    df = df[df["profile"].isin(profiles)].copy()

    if df.empty:
        raise SystemExit(f"No valid rows after filtering for duration={duration}.")

    # Baseline A: regular only
    X_reg = df[df["profile"] == "regular"][feat_cols].to_numpy()
    if X_reg.shape[0] < 2:
        raise SystemExit("Not enough regular-user runs to train baseline.")

    scaler_a, clf_a, scores_a = fit_model(X_reg, seed=args.seed, n_estimators=args.n_estimators)
    thr_a = threshold_from_train(scores_a, mode=args.threshold, q=args.q)

    rates_a: Dict[str, float] = {}
    for p in profiles:
        Xp = df[df["profile"] == p][feat_cols].to_numpy()
        rates_a[p] = flagged_rate(scaler_a, clf_a, thr_a, Xp)

    # Baseline B: mixed
    X_mix = df[feat_cols].to_numpy()
    scaler_b, clf_b, scores_b = fit_model(X_mix, seed=args.seed, n_estimators=args.n_estimators)
    thr_b = threshold_from_train(scores_b, mode=args.threshold, q=args.q)

    rates_b: Dict[str, float] = {}
    for p in profiles:
        Xp = df[df["profile"] == p][feat_cols].to_numpy()
        rates_b[p] = flagged_rate(scaler_b, clf_b, thr_b, Xp)

    # Report
    print(f"Duration: {duration}")
    print(f"Feature columns ({len(feat_cols)}): {', '.join(feat_cols)}")
    print(f"Threshold mode: {args.threshold}" + (f" (q={args.q})" if args.threshold == "quantile" else ""))
    print()
    print("Baseline A: train on Regular only")
    for p in profiles:
        print(f"  {p:8s} flagged: {fmt_pct(rates_a[p])}%")
    print()
    print("Baseline B: train on Mixed profiles")
    for p in profiles:
        print(f"  {p:8s} flagged: {fmt_pct(rates_b[p])}%")

    # Optional LaTeX
    if args.out_tex:
        tex = make_latex_table(duration, rates_a, rates_b)
        Path(args.out_tex).write_text(tex, encoding="utf-8")
        print()
        print(f"[done] Wrote LaTeX table to: {args.out_tex}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
