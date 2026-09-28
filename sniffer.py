#!/usr/bin/env python3
"""Small, explainable packet analyzer for learning and authorized lab use."""

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from scapy.all import rdpcap, sniff, wrpcap
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTPRequest


PACKETS = []
FINDINGS = []
PROTOCOLS = Counter()
FLOWS = Counter()
HOST_PACKETS = Counter()
HOST_BYTES = Counter()
SENSITIVE_PORTS = {21: "FTP", 23: "Telnet", 445: "SMB"}
PORT_NAMES = {53: "DNS", 80: "HTTP", 443: "HTTPS", 22: "SSH", 25: "SMTP"}


def short_id(value):
    """Stable pseudonym for report output; raw IPs stay out of exported reports."""
    return "host-" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]


def describe_packet(packet, number):
    if not packet.haslayer(IP):
        return None

    ip = packet[IP]
    src, dst = ip.src, ip.dst
    size = len(packet)
    sport = dport = None
    if packet.haslayer(TCP):
        protocol = "TCP"
        sport, dport = int(packet[TCP].sport), int(packet[TCP].dport)
    elif packet.haslayer(UDP):
        protocol = "UDP"
        sport, dport = int(packet[UDP].sport), int(packet[UDP].dport)
    elif packet.haslayer(ICMP):
        protocol = "ICMP"
    else:
        protocol = "IP"

    PROTOCOLS[protocol] += 1
    HOST_PACKETS[src] += 1
    HOST_BYTES[src] += size
    flow = (src, dst, protocol, sport, dport)
    FLOWS[flow] += 1

    details = []
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        try:
            domain = packet[DNSQR].qname.decode("utf-8", "replace").rstrip(".")
            details.append(f"DNS lookup for {domain}")
        except Exception:
            details.append("DNS query")
    elif packet.haslayer(HTTPRequest):
        try:
            host = packet[HTTPRequest].Host.decode("utf-8", "replace")
            path = packet[HTTPRequest].Path.decode("utf-8", "replace")
            details.append(f"HTTP request to {host}{path}")
        except Exception:
            details.append("HTTP request")
    elif protocol in ("TCP", "UDP") and dport:
        service = PORT_NAMES.get(dport)
        if service:
            details.append(f"{service} traffic")
    if not details:
        details.append(f"{protocol} traffic")

    summary = {
        "number": number,
        "time": datetime.fromtimestamp(float(packet.time), timezone.utc).isoformat(),
        "source": src,
        "destination": dst,
        "protocol": protocol,
        "source_port": sport,
        "destination_port": dport,
        "bytes": size,
        "summary": f"{src} sent {size} bytes to {dst}: " + ", ".join(details),
    }
    return summary


def assess(summary):
    """Transparent rules create explainable, educational findings."""
    src, dst = summary["source"], summary["destination"]
    port = summary["destination_port"]
    if port in SENSITIVE_PORTS:
        service = SENSITIVE_PORTS[port]
        FINDINGS.append({
            "severity": "HIGH" if port == 23 else "MEDIUM",
            "reason": f"Traffic used {service} (destination port {port}), which is often unencrypted.",
            "source": src, "destination": dst, "packet": summary["number"],
        })
    if summary["bytes"] >= 1500:
        FINDINGS.append({
            "severity": "LOW",
            "reason": f"Large IP packet observed ({summary['bytes']} bytes).",
            "source": src, "destination": dst, "packet": summary["number"],
        })


def assess_capture_patterns(summaries):
    """Flag simple volume and port-scan patterns in this short capture window."""
    ports_by_source = defaultdict(set)
    first_packet_by_source = {}
    for item in summaries:
        source = item["source"]
        first_packet_by_source.setdefault(source, item["number"])
        if item["destination_port"] is not None:
            ports_by_source[source].add(item["destination_port"])

    for source, packet_total in HOST_PACKETS.items():
        if packet_total >= 25:
            FINDINGS.append({
                "severity": "LOW",
                "reason": f"High capture-window traffic volume from one host ({packet_total} packets).",
                "source": source, "destination": source,
                "packet": first_packet_by_source.get(source, 0),
            })
        port_count = len(ports_by_source[source])
        if port_count >= 10:
            FINDINGS.append({
                "severity": "MEDIUM",
                "reason": f"One host contacted {port_count} different destination ports; this can indicate service probing.",
                "source": source, "destination": source,
                "packet": first_packet_by_source.get(source, 0),
            })


def redacted_report(summaries):
    # Export only metadata and pseudonymous hosts. Packet payloads and raw IPs are omitted.
    clean = []
    for item in summaries:
        clean.append({
            "time": item["time"],
            "source": short_id(item["source"]),
            "destination": short_id(item["destination"]),
            "protocol": item["protocol"],
            "source_port": item["source_port"],
            "destination_port": item["destination_port"],
            "bytes": item["bytes"],
            "summary": f"{short_id(item['source'])} sent {item['bytes']} bytes to "
                       f"{short_id(item['destination'])}: {item['protocol']} traffic",
        })
    findings = [{
        **finding,
        "source": short_id(finding["source"]),
        "destination": short_id(finding["destination"]),
    } for finding in FINDINGS]
    findings.sort(key=lambda f: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(f["severity"], 3))
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "privacy_note": "IP addresses are pseudonymized; packet payloads, DNS names, and HTTP paths are not exported.",
        "packet_count": len(clean),
        "protocols": dict(PROTOCOLS),
        "conversations": [{
            "source": short_id(flow[0]), "destination": short_id(flow[1]),
            "protocol": flow[2], "source_port": flow[3], "destination_port": flow[4],
            "packets": count,
        } for flow, count in FLOWS.most_common()],
        "findings": findings,
        "packets": clean,
    }


def print_report(summaries):
    print("\n=== Traffic overview ===")
    print(f"IP packets analyzed: {len(summaries)}")
    print("Protocols: " + (", ".join(f"{p}={n}" for p, n in PROTOCOLS.most_common()) or "none"))
    print(f"Conversations: {len(FLOWS)}")
    print("\n=== Risk-ranked findings ===")
    if not FINDINGS:
        print("No configured heuristic alerts.")
    else:
        ordered = sorted(FINDINGS, key=lambda f: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}[f["severity"]])
        for finding in ordered:
            print(f"[{finding['severity']}] packet {finding['packet']}: {finding['reason']}")
    print("\n=== Conversation summary ===")
    for flow, count in FLOWS.most_common(10):
        src, dst, proto, sport, dport = flow
        print(f"{src}:{sport or '-'} -> {dst}:{dport or '-'} ({proto}), {count} packet(s)")


def main():
    parser = argparse.ArgumentParser(description="Capture and explain network metadata.")
    parser.add_argument("--read-pcap", help="analyze a saved PCAP file instead of live capture")
    parser.add_argument("--interface", help="network interface to capture on")
    parser.add_argument("--filter", dest="capture_filter", help="optional BPF filter, e.g. 'tcp port 80'")
    parser.add_argument("--count", type=int, default=100, help="maximum packets to capture (default: 100)")
    parser.add_argument("--timeout", type=int, default=30, help="capture time limit in seconds (default: 30)")
    parser.add_argument("--save-pcap", help="optional path to save captured packets (may contain sensitive data)")
    parser.add_argument("--export", help="optional redacted report path (.json or .csv)")
    args = parser.parse_args()

    if args.count < 1 or args.timeout < 1:
        parser.error("--count and --timeout must be positive")

    print("Packet Sniffer Analyzer — capture only on networks you are authorized to inspect.")
    try:
        if args.read_pcap:
            print(f"Reading saved capture: {args.read_pcap}")
            PACKETS.extend(rdpcap(args.read_pcap))
        else:
            print(f"Capturing up to {args.count} packets for at most {args.timeout} seconds.")
            PACKETS.extend(sniff(
                iface=args.interface, filter=args.capture_filter, count=args.count,
                timeout=args.timeout, store=True,
            ))
    except PermissionError:
        parser.error("Packet capture needs appropriate operating-system permissions.")
    except (OSError, ValueError) as exc:
        parser.error(f"Capture failed: {exc}")

    summaries = []
    for number, packet in enumerate(PACKETS, 1):
        summary = describe_packet(packet, number)
        if summary:
            summaries.append(summary)
            assess(summary)
            print(f"#{number} {summary['summary']} [{summary['bytes']} bytes]")

    assess_capture_patterns(summaries)
    print_report(summaries)

    if args.save_pcap:
        wrpcap(args.save_pcap, PACKETS)
        print(f"Raw capture saved to {args.save_pcap}. It may contain sensitive packet data.")
    if args.export:
        report = redacted_report(summaries)
        path = Path(args.export)
        if path.suffix.lower() == ".csv":
            with path.open("w", newline="", encoding="utf-8") as handle:
                rows = report["packets"]
                writer = csv.DictWriter(handle, fieldnames=list(rows[0]) if rows else [
                    "time", "source", "destination", "protocol", "source_port",
                    "destination_port", "bytes", "summary",
                ])
                writer.writeheader()
                writer.writerows(rows)
            print(f"Redacted packet summary exported to {path} (CSV contains packets only).")
        else:
            path.write_text(json.dumps(report, indent=2), encoding="utf-8")
            print(f"Redacted analysis report exported to {path}.")


if __name__ == "__main__":
    main()
