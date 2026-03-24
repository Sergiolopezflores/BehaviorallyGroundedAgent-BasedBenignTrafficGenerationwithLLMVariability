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
- Capture performed inside each guest on the primary guest interface  

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
