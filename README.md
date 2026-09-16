# Network Traffic Analysis & NIDS Rule Engine

Custom Suricata signatures, Zeek protocol logs, and `tshark` extraction scripts built and tested on an Ubuntu Server VirtualBox laboratory.

```
Attacker Node (192.168.56.105) ---> [vboxnet0] ---> Target Node (192.168.56.106 - enp0s8)
                                                     ├── Suricata (NIDS)
                                                     ├── Zeek Telemetry Engine
                                                     └── tshark CLI Analysis
```

---

### Custom Suricata Rules (`config/suricata/local.rules`)

Engineered specific signatures to catch HTTP command injection, path traversal, and unauthorized outbound connections:

```suricata
# Detect HTTP Command Injection Parameter Passing
alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"LOCAL SURICATA HTTP Command Injection Attempt"; flow:established,to_server; content:"cmd.php"; nocase; content:"cmd="; nocase; classtype:web-application-attack; sid:1000001; rev:1;)

# Detect Sensitive Environment File Probe
alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"LOCAL SURICATA Sensitive .env File Request"; flow:established,to_server; content:".env"; nocase; classtype:attempted-recon; sid:1000006; rev:1;)

# Outbound Reverse Shell / Non-Standard Listener
alert tcp $HOME_NET any -> $EXTERNAL_NET !443 (msg:"LOCAL SURICATA Outbound Unencrypted Shell Port 4444"; flow:to_server; dst_port:4444; classtype:trojan-activity; sid:1000005; rev:1;)
```

---

### VirtualBox NIC Offloading Fix (`config/suricata/suricata_override.yaml`)

VirtualBox Host-Only interfaces (`vboxnet0`) handle TCP checksum offloading in software on the host OS. Suricata drops incoming frames with invalid checksums by default. 

To enable full rule evaluation in VirtualBox:

```yaml
af-packet:
  - interface: enp0s8
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    checksum-validation: no  # Required for VirtualBox host-only traffic
```

---

### CLI Telemetry Parsing (`scripts/tshark_analysis.sh`)

Quick syntax snippets for PCAP extraction:

```bash
# Pull HTTP GET/POST requests with source IP, Host, and URI
tshark -r pcaps/lab_capture.pcap -Y "http.request" \
  -T fields -e frame.time -e ip.src -e ip.dst -e http.host -e http.request.method -e http.request.uri

# Aggregate SYN packets to spot port scanning sweeps
tshark -r pcaps/lab_capture.pcap -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0" \
  -T fields -e ip.src -e ip.dst -e tcp.dstport | sort | uniq -c | sort -nr
```

---

### Sample Telemetry Logs

**Zeek HTTP Transaction (`zeek/logs/http.log`)**:
```tsv
1726409415.819201	C8mN1X5V4b9Q2z	192.168.56.105	49212	192.168.56.106	80	1	GET	192.168.56.106	/cmd.php?cmd=cat%20/etc/passwd	-	1.1	curl/7.88.1	-	0	148	200	OK
```

**Suricata EVE Alert JSON (`suricata/logs/eve.json`)**:
```json
{"timestamp":"2026-09-15T14:10:15.819201+0000","flow_id":192837465,"in_iface":"enp0s8","event_type":"alert","src_ip":"192.168.56.105","src_port":49212,"dest_ip":"192.168.56.106","dest_port":80,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":1000001,"rev":1,"signature":"LOCAL SURICATA HTTP Command Injection Attempt","category":"Web Application Attack","severity":1}}
```

---

### Repository Layout

- `config/suricata/` – Custom detection rules and YAML interface settings
- `zeek/logs/` – Standard TSV session logs (`conn.log`, `http.log`, `dns.log`)
- `suricata/logs/` – Text (`fast.log`) and structured JSON (`eve.json`) alerts
- `scripts/` – Tshark triage script (`tshark_analysis.sh`)
