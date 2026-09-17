# Network Traffic Analysis & NIDS Rule Engineering

---

## Overview

This repository documents hands-on network security monitoring (NSM), packet analysis, and signature-based Intrusion Detection System (NIDS) rule development conducted on an Ubuntu Server VirtualBox virtual machine (`192.168.56.106`).

The lab combines CLI packet extraction via **`tshark`**, protocol telemetry generation via **`Zeek`**, and real-time alert generation via **`Suricata`**.

---

## Network Monitoring Architecture

```
Attacker Node (192.168.56.105) ---> [vboxnet0] ---> Target Node (192.168.56.106 - enp0s8)
                                                     ├── tshark (CLI Packet Capture)
                                                     ├── Zeek Engine (conn.log, http.log, dns.log)
                                                     └── Suricata NIDS (local.rules Engine)
```

---

## Custom NIDS Detection Rules (`config/suricata/local.rules`)

Custom Suricata signatures authored to detect web application attacks and unauthorized outbound connections:

```suricata
# 1. HTTP Command Injection Parameter Passing
alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"LOCAL SURICATA HTTP Command Injection Attempt"; flow:established,to_server; content:"cmd.php"; nocase; content:"cmd="; nocase; classtype:web-application-attack; sid:1000001; rev:1;)

# 2. Sensitive Environment File Request Probe
alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"LOCAL SURICATA Sensitive .env File Request"; flow:established,to_server; content:".env"; nocase; classtype:attempted-recon; sid:1000006; rev:1;)

# 3. Outbound Reverse Shell to Non-Standard Port
alert tcp $HOME_NET any -> $EXTERNAL_NET !443 (msg:"LOCAL SURICATA Outbound Unencrypted Shell Port 4444"; flow:to_server; dst_port:4444; classtype:trojan-activity; sid:1000005; rev:1;)
```

---

## VirtualBox Checksum Offload Fix (`config/suricata/suricata_override.yaml`)

VirtualBox Host-Only interfaces (`vboxnet0`) offload TCP checksum calculations to the host operating system. Suricata drops incoming frames with uncalculated TCP checksums by default.

Disabling internal checksum validation in Suricata enables full rule matching across virtual host-only interfaces:

```yaml
af-packet:
  - interface: enp0s8
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    checksum-validation: no  # Essential setting for VirtualBox host-only NICs
```

---

## CLI Packet Extraction (`scripts/tshark_analysis.sh`)

### HTTP Request Telemetry Extraction
```bash
tshark -r pcaps/lab_capture.pcap -Y "http.request" \
  -T fields -e frame.time -e ip.src -e ip.dst -e http.host -e http.request.method -e http.request.uri
```

### TCP SYN Scan Detection
```bash
tshark -r pcaps/lab_capture.pcap -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0" \
  -T fields -e ip.src -e ip.dst -e tcp.dstport | sort | uniq -c | sort -nr
```

---

## Telemetry Artifacts

### 1. Zeek HTTP Telemetry (`zeek/logs/http.log`)
```tsv
1726409415.819201	C8mN1X5V4b9Q2z	192.168.56.105	49212	192.168.56.106	80	1	GET	192.168.56.106	/cmd.php?cmd=cat%20/etc/passwd	-	1.1	curl/7.88.1	-	0	148	200	OK
```

### 2. Suricata Structured Alert Record (`suricata/logs/eve.json`)
```json
{"timestamp":"2026-09-15T14:10:15.819201+0000","flow_id":192837465,"in_iface":"enp0s8","event_type":"alert","src_ip":"192.168.56.105","src_port":49212,"dest_ip":"192.168.56.106","dest_port":80,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":1000001,"rev":1,"signature":"LOCAL SURICATA HTTP Command Injection Attempt","category":"Web Application Attack","severity":1}}
```

---

## Repository Structure

```
.
├── config/
│   └── suricata/
│       ├── local.rules              # Custom Suricata detection signatures
│       └── suricata_override.yaml   # Interface tuning & checksum config
├── zeek/
│   └── logs/
│       ├── conn.log                 # Zeek connection session records
│       ├── http.log                 # Zeek HTTP transaction telemetry
│       └── dns.log                  # Zeek DNS query records
├── suricata/
│   └── logs/
│       ├── fast.log                 # Standard text alert output
│       └── eve.json                 # Suricata EVE JSON event alerts
└── scripts/
    └── tshark_analysis.sh           # Automated pcap triage helper script
```
