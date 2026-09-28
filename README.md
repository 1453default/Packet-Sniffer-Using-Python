# Packet Sniffer Analyzer

A small Python/Scapy project for learning about packet capture and basic traffic analysis. Use it only on networks you own or have permission to inspect.

## Features

- **Plain-language summaries:** highlights DNS lookups, HTTP requests, and common services.
- **Explainable anomaly heuristics:** flags potentially risky cleartext services (FTP/Telnet/SMB) and unusually large IP packets. These are simple rules, not machine learning and not proof of an attack.
- **Risk-ranked findings:** prints HIGH, MEDIUM, and LOW findings with the packet number and reason.
- **Protocol and conversation overview:** counts protocols and the most active source/destination conversations.
- **Privacy-aware export:** JSON reports pseudonymize IP addresses and omit packet payloads, DNS names, and HTTP paths. CSV exports only redacted packet metadata. Raw PCAP saving is optional and may contain sensitive information.

## Setup

Python 3.9 or newer is recommended.

```bash
python -m pip install -r requirements.txt
```

Packet capture may require administrator/root privileges. On Windows, install Npcap and allow the application to use it.

## Run

Capture up to 100 packets or for 30 seconds:

```bash
python sniffer.py
```

Choose an interface, capture filter, packet limit, or timeout:

```bash
python sniffer.py --interface <interface> --filter "tcp" --count 200 --timeout 60
```

Replay an existing PCAP without live capture permissions, then export a privacy-filtered JSON report or CSV packet summary:

```bash
python sniffer.py --read-pcap capture.pcap --export report.json
python sniffer.py --read-pcap capture.pcap --export packets.csv
```

Save a raw capture only when needed:

```bash
python sniffer.py --save-pcap capture.pcap --export report.json
```

The JSON/CSV report omits payload contents. A PCAP can contain private traffic; store and share it carefully. Avoid capturing traffic that you are not authorized to inspect.
