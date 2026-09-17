# Network Traffic Analysis & Suricata Rules

tshark commands, Zeek logs, and custom Suricata signatures tested on an Ubuntu Server VirtualBox setup.

### Suricata Rules (`config/suricata/local.rules`)
```suricata
alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"LOCAL SURICATA HTTP Command Injection Attempt"; flow:established,to_server; content:"cmd.php"; nocase; content:"cmd="; nocase; classtype:web-application-attack; sid:1000001; rev:1;)
alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"LOCAL SURICATA Sensitive .env File Request"; flow:established,to_server; content:".env"; nocase; classtype:attempted-recon; sid:1000006; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET !443 (msg:"LOCAL SURICATA Outbound Unencrypted Shell Port 4444"; flow:to_server; dst_port:4444; classtype:trojan-activity; sid:1000005; rev:1;)
```

### VirtualBox Checksum Offload Fix (`config/suricata/suricata_override.yaml`)
VirtualBox host-only interfaces (`vboxnet0`) offload TCP checksums in host memory, causing Suricata to drop incoming frames with invalid checksums. Disabled checksum validation:
```yaml
af-packet:
  - interface: enp0s8
    checksum-validation: no
```

### tshark Commands
```bash
tshark -r pcaps/lab_capture.pcap -Y "http.request" -T fields -e frame.time -e ip.src -e ip.dst -e http.host -e http.request.method -e http.request.uri
tshark -r pcaps/lab_capture.pcap -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0" -T fields -e ip.src -e ip.dst -e tcp.dstport | sort | uniq -c | sort -nr
```

### Zeek Log Sample (`zeek/logs/http.log`)
```tsv
1726409415.819201	C8mN1X5V4b9Q2z	192.168.56.105	49212	192.168.56.106	80	1	GET	192.168.56.106	/cmd.php?cmd=cat%20/etc/passwd	-	1.1	curl/7.88.1	-	0	148	200	OK
```
