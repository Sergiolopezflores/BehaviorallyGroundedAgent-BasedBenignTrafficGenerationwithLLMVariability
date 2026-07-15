# Methodology

## Step 1: extract the benign host

```bash
tshark \
    -r Monday-WorkingHours.pcap \
    -Y "ip.addr == 192.168.10.14" \
    -w win10_14.pcap
```

## Step 2: reorder packets

```bash
reordercap \
    win10_14.pcap \
    win10_14_sorted.pcap
```

## Step 3: split into windows

```bash
editcap \
    -i 900 \
    win10_14_sorted.pcap \
    windows/window.pcapng
```

## Step 4: compute metrics

```bash
python extract_window_metrics.py \
    --manifest cicids2017_manifest.csv \
    --output cicids2017_metrics.csv
```

## Step 5: summarize results

```bash
python summarize_window_metrics.py \
    --input cicids2017_metrics.csv \
    --output cicids2017_summary.csv
```
