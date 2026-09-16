#!/bin/bash
# tshark_analysis.sh - Helper script for extracting network telemetry from PCAP captures
# Used during lab investigation on Ubuntu Server (192.168.56.106)

PCAP_FILE="${1:-pcaps/lab_capture.pcap}"

if [ ! -f "$PCAP_FILE" ]; then
    echo "[!] Usage: $0 <path_to_pcap>"
    echo "[!] PCAP file not found: $PCAP_FILE"
    exit 1
fi

echo "=================================================="
echo " Network Traffic Analysis Summary: $PCAP_FILE"
echo "=================================================="

echo ""
echo "[+] Top 10 Source IP Addresses by Packet Count:"
tshark -r "$PCAP_FILE" -q -z ip,hosts,tree | head -n 20 2>/dev/null || \
tshark -r "$PCAP_FILE" -T fields -e ip.src | sort | uniq -c | sort -nr | head -n 10

echo ""
echo "[+] Protocol Breakdown:"
tshark -r "$PCAP_FILE" -q -z io,phs

echo ""
echo "[+] HTTP Requests Detected:"
tshark -r "$PCAP_FILE" -Y "http.request" -T fields -e frame.time -e ip.src -e ip.dst -e http.host -e http.request.method -e http.request.uri 2>/dev/null

echo ""
echo "[+] DNS Queries Filtered:"
tshark -r "$PCAP_FILE" -Y "dns.flags.response == 0" -T fields -e ip.src -e dns.qry.name -e dns.qry.type 2>/dev/null | head -n 15

echo ""
echo "[+] Suspicious TCP SYN Scans (High Port Count):"
tshark -r "$PCAP_FILE" -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0" -T fields -e ip.src -e ip.dst -e tcp.dstport | sort | uniq -c | sort -nr | head -n 10

echo ""
echo "[+] Capture Analysis Complete."
