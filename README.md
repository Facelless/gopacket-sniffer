# Mini Wireshark in Go

![Go](https://img.shields.io/badge/Go-1.20%2B-blue?logo=go&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)

A **network packet sniffer** built in Go, inspired by Wireshark, that captures, analyzes, and saves network packets in real-time. Ideal for learning network protocols, traffic analysis, and debugging network applications.  

---

## Features

- Automatically detects available network interfaces.  
- Captures packets in **promiscuous mode** (TCP, UDP, ICMP, ARP, and more).  
- Apply **BPF filters** to capture only specific traffic.  
- Displays detailed packet info:
  - Source and destination IP addresses  
  - Network and transport protocol details  
  - TCP flags (SYN, ACK, FIN, RST, etc.)  
  - TCP sequence numbers  
  - Payload in hexadecimal format  
- Real-time counters for each protocol.  
- Saves all captured packets in `.pcap` format for Wireshark analysis.  

---

## Installation

1. Install **Go (1.20+)** if not installed. You can download it from [https://golang.org/dl/](https://golang.org/dl/).  

2. Clone the repository:

```bash
git clone https://github.com/yourusername/gopacket-sniffer.git
cd gopacket-sniffer
```

## Install dependencies:

```bash
go get github.com/google/gopacket
go get github.com/google/gopacket/pcap
go get github.com/google/gopacket/pcapgo

```

## Usage
Run directly with go run:

```bash
sudo go run main.go
```

## Using BPF filters:

```bash
sudo ./sniffer "tcp"          # Only TCP packets
sudo ./sniffer "udp"          # Only UDP packets
sudo ./sniffer "icmp"         # Only ICMP packets
sudo ./sniffer "tcp port 80"  # Only HTTP traffic
sudo ./sniffer "tcp or udp"   # Capture TCP and UDP packets
```


## Output
![Uploading](https://i.postimg.cc/NffKmQCN/image.png)
