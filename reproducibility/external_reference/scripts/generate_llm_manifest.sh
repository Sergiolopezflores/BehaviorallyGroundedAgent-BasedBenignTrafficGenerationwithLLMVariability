#!/bin/bash

OUTPUT="llm_windows_manifest.csv"

echo "pcap,source,dataset,profile,host,local_ip,nominal_duration_s,include" > "$OUTPUT"

BASE="/Users/antoniomunoz/Desktop/PROYECTOS/BENIGM AGENT/exp1/llm"

LOCAL_IP="192.168.18.134"

for run_dir in "$BASE"/run_*; do

    run_name=$(basename "$run_dir")

    pcap="$run_dir/capture.pcap"

    echo "$pcap,generated,BENIGN-AGENT,llm,$run_name,$LOCAL_IP,900,true" \
        >> "$OUTPUT"

done

echo "Generated: $OUTPUT"

