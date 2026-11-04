#!/bin/bash

# HTTP Request Telemetry Extraction
# Extracts HTTP request details from a PCAP file
# Usage: ./tshark_analysis.sh http pcaps/lab_capture.pcap

# TCP SYN Scan Detection
# Identifies potential port scans by counting SYN packets
# Usage: ./tshark_analysis.sh syn pcaps/lab_capture.pcap

# DNS Query Analysis
# Analyzes DNS queries for suspicious patterns
# Usage: ./tshark_analysis.sh dns pcaps/lab_capture.pcap

case "$1" in
    http)
        echo "Extracting HTTP request details..."
        tshark -r "$2" -Y "http.request" \
            -T fields -e frame.time -e ip.src -e ip.dst -e http.host -e http.request.method -e http.request.uri
        ;;
    syn)
        echo "Detecting TCP SYN scans..."
        tshark -r "$2" -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0" \
            -T fields -e ip.src -e ip.dst -e tcp.dstport | sort | uniq -c | sort -nr
        ;;
    dns)
        echo "Analyzing DNS queries..."
        tshark -r "$2" -Y "dns" \
            -T fields -e frame.time -e ip.src -e ip.dst -e dns.qry.name -e dns.qry.type
        ;;
    *)
        echo "Usage: $0 {http|syn|dns} <pcap_file>"
        exit 1
        ;;
esac