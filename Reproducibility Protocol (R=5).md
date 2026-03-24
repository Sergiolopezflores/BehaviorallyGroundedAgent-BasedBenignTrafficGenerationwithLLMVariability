# Reproducibility Protocol (R=5) — End-to-end

## 1. Scope and experimental matrix

We reproduce the capture matrix used in the paper:

- **Profiles:** Regular, Gamer, Administrator  
- **Durations:** T ∈ {5m, 15m, 60m}  
- **Replications:** R = 5 independent runs per (profile, T)  

**Total captures expected:**  
3 × 3 × 5 = **45 PCAP/PCAPNG files**

Each run produces:

- A capture file (`.pcapng` recommended)
- Optional log (`.log`, recommended for traceability)

---

## 2. Prerequisites

### 2.1 Virtualization and network isolation

- **Hypervisor:** Oracle VM VirtualBox  
- Capture performed **inside each guest** on the primary guest interface  

**Network modes:**

- Regular + Gamer → NAT  
- Administrator → Host-only (multi-VM internal network)

### 2.2 Tools required on the analysis machine (macOS)

Install Wireshark CLI tools:

- `tshark`
- `capinfos`

Ensure they are in **PATH**.

- Python **3.10+** recommended.

---

## 3. Independent runs and clean snapshots

To satisfy **independent runs**:

For each profile VM:

- Disable automatic updates where possible  
- Gamer profile → snapshot **after updates** (“post-update snapshot”)  
- Create a clean snapshot (e.g. `clean_snapshot`)

For each run:

1. Restore `clean_snapshot`
2. Start capture
3. Run the agent for exactly duration **T**
4. Stop capture
5. Save capture file with deterministic naming

Optional (recommended):

- If agent supports RNG seeds → use `seed = run_index (1..5)`
- Store stdout/stderr logs per run

---

## 4. Capture naming and folder layout

### 4.1 Recommended repository layout

```
repro/
  pcaps/
    regular/5m/run1.pcapng ... run5.pcapng
    regular/15m/...
    regular/60m/...
    gamer/...
    admin/...
  derived/
    captures_summary.csv
    flows_metrics.csv
    qc_report.txt
    tables/
      table_flow_structure.tex
      table_sanity_iforest.tex (optional)
  logs/ (optional)
    regular/15m/run1.log ...
  scripts/
    pcapng_batch_to_csv.py
    qc_captures.py
    pcapng_flows_to_csv_and_table.py
    sanity_iforest.py (optional)

```


### 4.2 Flat naming convention support

If captures are in a single folder:

--input-dir
--pattern "capturaAgente*.pcapng"


---

## 5. Generate `captures_summary.csv`

Script: scripts/pcapng_batch_to_csv.py


Outputs per-capture metrics:

- `bytes_total`
- `packets_total`
- `mean_bps`
- `peak_mbps_1s`
- `tcp_pkts`
- `udp_pkts`
- `icmp_pkts`
- `other_pkts`
- `udp443_pkts` (QUIC-like indicator)
- Top destination ports

Run:

```bash
python3 scripts/pcapng_batch_to_csv.py \
  --input-dir repro/pcaps \
  --recursive \
  --pattern "*.pcapng" \
  --output repro/derived/captures_summary.csv
```

## 6. QC: identify truncated / invalid captures

Script: scripts/qc_captures.py

Run:

```bash
python3 scripts/qc_captures.py \
  --csv repro/derived/captures_summary.csv \
  --out repro/derived/qc_report.txt
```

Re-capture files flagged by:

- capinfos_truncated = 1
- tshark_truncated(...)
- Duration out of expected range


## 7. Flow metrics and Table 5 (bidirectional 5-tuples)

Script: scripts/pcapng_flows_to_csv_and_table.py

Flow definition:

- Key = protocol + unordered pair (IP, port)
- Bytes = sum of frame.len
- Duration = last_ts − first_ts
- Packets = count per flow
- ICMP / non-TCP-UDP excluded

Run:

```bash
python3 scripts/pcapng_flows_to_csv_and_table.py \
  --input-dir repro/pcaps \
  --recursive \
  --pattern "*.pcapng" \
  --out-csv repro/derived/flows_metrics.csv \
  --out-tex repro/derived/tables/table_flow_structure.tex
```

Outputs:

- flows_metrics.csv
- table_flow_structure.tex


## 8. Optional IDS/NDR sanity-check (Isolation Forest)

Script: scripts/sanity_iforest.py

### 8.1 Create Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install pandas scikit-learn
```

### 8.2 Run sanity-check (T = 15m)
```bash
python scripts/sanity_iforest.py \
  --captures repro/derived/captures_summary.csv \
  --flows repro/derived/flows_metrics.csv \
  --duration 15m \
  --threshold quantile \
  --q 0.05 \
  --out-tex repro/derived/tables/table_sanity_iforest.tex
```

### 8.3 Robustness across seeds
```bash
for s in 0 1 2; do
  python scripts/sanity_iforest.py \
    --captures repro/derived/captures_summary.csv \
    --flows repro/derived/flows_metrics.csv \
    --duration 15m \
    --threshold quantile \
    --q 0.05 \
    --seed $s
done
```

Deactivate:

deactivate

