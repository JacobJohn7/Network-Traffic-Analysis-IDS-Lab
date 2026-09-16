# PCAP Storage Note

Raw `.pcap` capture files captured during lab execution (`lab_capture.pcap`) are excluded from repository tracking via `.gitignore` to prevent repository bloat.

To generate new PCAPs in the lab environment:
```bash
sudo tshark -i enp0s8 -w pcaps/lab_capture.pcap -f "tcp or udp"
```
