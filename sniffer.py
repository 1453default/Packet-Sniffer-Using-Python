#!/usr/bin/env python3

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

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box


# ============================================================
# CONFIGURATION
# ============================================================

console = Console()

PACKETS = []
FINDINGS = []
PROTOCOLS = Counter()
FLOWS = Counter()
HOST_PACKETS = Counter()
HOST_BYTES = Counter()

SENSITIVE_PORTS = {
    21: "FTP",
    23: "Telnet",
    445: "SMB",
}

PORT_NAMES = {
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    22: "SSH",
    25: "SMTP",
}


# ============================================================
# HELPERS
# ============================================================

def short_id(value):
    """Stable pseudonym for exported reports."""
    return "host-" + hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()[:8]


def protocol_style(protocol):
    styles = {
        "TCP": "cyan",
        "UDP": "magenta",
        "ICMP": "yellow",
        "IP": "white",
    }
    return styles.get(protocol, "white")


def severity_style(severity):
    styles = {
        "HIGH": "bold red",
        "MEDIUM": "bold yellow",
        "LOW": "green",
    }
    return styles.get(severity, "white")


def clear_screen():
    console.clear()


def print_banner(mode):
    banner = Text()
    banner.append("PACKET SNIFFER ANALYZER\n", style="bold cyan")
    banner.append("Network Traffic Monitoring & Analysis\n", style="white")
    banner.append(f"Mode: {mode}", style="bold green")

    console.print(
        Panel(
            banner,
            border_style="bright_blue",
            box=box.DOUBLE,
            padding=(1, 4),
        )
    )


# ============================================================
# PACKET ANALYSIS
# ============================================================

def describe_packet(packet, number):
    if not packet.haslayer(IP):
        return None

    ip = packet[IP]

    src = ip.src
    dst = ip.dst
    size = len(packet)

    sport = None
    dport = None

    if packet.haslayer(TCP):
        protocol = "TCP"
        sport = int(packet[TCP].sport)
        dport = int(packet[TCP].dport)

    elif packet.haslayer(UDP):
        protocol = "UDP"
        sport = int(packet[UDP].sport)
        dport = int(packet[UDP].dport)

    elif packet.haslayer(ICMP):
        protocol = "ICMP"

    else:
        protocol = "IP"

    PROTOCOLS[protocol] += 1
    HOST_PACKETS[src] += 1
    HOST_BYTES[src] += size

    flow = (
        src,
        dst,
        protocol,
        sport,
        dport,
    )

    FLOWS[flow] += 1

    details = []

    # DNS
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        try:
            domain = packet[DNSQR].qname.decode(
                "utf-8", "replace"
            ).rstrip(".")

            details.append(f"DNS lookup: {domain}")

        except Exception:
            details.append("DNS query")

    # HTTP
    elif packet.haslayer(HTTPRequest):
        try:
            host = packet[HTTPRequest].Host.decode(
                "utf-8", "replace"
            )

            path = packet[HTTPRequest].Path.decode(
                "utf-8", "replace"
            )

            details.append(
                f"HTTP request: {host}{path}"
            )

        except Exception:
            details.append("HTTP request")

    # Known ports
    elif protocol in ("TCP", "UDP") and dport:

        service = PORT_NAMES.get(dport)

        if service:
            details.append(
                f"{service} traffic"
            )

    if not details:
        details.append(
            f"{protocol} traffic"
        )

    return {
        "number": number,
        "time": datetime.fromtimestamp(
            float(packet.time),
            timezone.utc
        ).isoformat(),

        "source": src,
        "destination": dst,

        "protocol": protocol,

        "source_port": sport,
        "destination_port": dport,

        "bytes": size,

        "details": ", ".join(details),

        "summary":
            f"{src} sent {size} bytes to {dst}: "
            + ", ".join(details),
    }


# ============================================================
# SECURITY CHECKS
# ============================================================

def assess(summary):

    src = summary["source"]
    dst = summary["destination"]
    port = summary["destination_port"]

    # Sensitive services
    if port in SENSITIVE_PORTS:

        service = SENSITIVE_PORTS[port]

        FINDINGS.append({
            "severity":
                "HIGH" if port == 23 else "MEDIUM",

            "reason":
                f"Traffic used {service} "
                f"(destination port {port}), "
                f"which is often unencrypted.",

            "source": src,
            "destination": dst,

            "packet": summary["number"],
        })

    # Large packet
    if summary["bytes"] >= 1500:

        FINDINGS.append({
            "severity": "LOW",

            "reason":
                f"Large IP packet observed "
                f"({summary['bytes']} bytes).",

            "source": src,
            "destination": dst,

            "packet": summary["number"],
        })


def assess_capture_patterns(summaries):

    ports_by_source = defaultdict(set)
    first_packet_by_source = {}

    for item in summaries:

        source = item["source"]

        first_packet_by_source.setdefault(
            source,
            item["number"]
        )

        if item["destination_port"] is not None:

            ports_by_source[source].add(
                item["destination_port"]
            )

    for source, packet_total in HOST_PACKETS.items():

        # High volume
        if packet_total >= 25:

            FINDINGS.append({
                "severity": "LOW",

                "reason":
                    f"High capture-window traffic "
                    f"volume from one host "
                    f"({packet_total} packets).",

                "source": source,
                "destination": source,

                "packet":
                    first_packet_by_source.get(
                        source,
                        0
                    ),
            })

        # Possible port probing
        port_count = len(
            ports_by_source[source]
        )

        if port_count >= 10:

            FINDINGS.append({
                "severity": "MEDIUM",

                "reason":
                    f"One host contacted "
                    f"{port_count} different "
                    f"destination ports; this can "
                    f"indicate service probing.",

                "source": source,
                "destination": source,

                "packet":
                    first_packet_by_source.get(
                        source,
                        0
                    ),
            })


# ============================================================
# RICH DISPLAY
# ============================================================

def display_packet(packet):

    table = Table(
        title="Live Packet Capture",
        box=box.ROUNDED,
        border_style="bright_blue",
        header_style="bold cyan",
        expand=True,
    )

    table.add_column("#", justify="right", width=5)
    table.add_column("Source", style="white")
    table.add_column("Destination", style="white")
    table.add_column("Protocol", justify="center")
    table.add_column("Bytes", justify="right")
    table.add_column("Details")

    protocol = packet["protocol"]

    table.add_row(
        str(packet["number"]),
        packet["source"],
        packet["destination"],

        Text(
            protocol,
            style=f"bold {protocol_style(protocol)}"
        ),

        f"{packet['bytes']:,}",

        packet["details"],
    )

    console.print(table)


def print_traffic_summary(summaries):

    total_bytes = sum(
        item["bytes"]
        for item in summaries
    )

    summary = Table(
        title="Traffic Overview",
        box=box.ROUNDED,
        border_style="green",
        header_style="bold green",
    )

    summary.add_column(
        "Metric",
        style="bold white"
    )

    summary.add_column(
        "Value",
        justify="right",
        style="bold cyan"
    )

    summary.add_row(
        "IP Packets Analyzed",
        f"{len(summaries):,}"
    )

    summary.add_row(
        "Total Traffic",
        f"{total_bytes:,} bytes"
    )

    summary.add_row(
        "Conversations",
        f"{len(FLOWS):,}"
    )

    for protocol, count in PROTOCOLS.most_common():

        summary.add_row(
            protocol,
            str(count)
        )

    console.print(summary)


def print_findings():

    console.print(
        Panel(
            "Security Heuristics",
            style="bold yellow",
            border_style="yellow",
        )
    )

    if not FINDINGS:

        console.print(
            Panel(
                "✓ No configured heuristic alerts.",
                style="bold green",
                border_style="green",
            )
        )

        return

    ordered = sorted(
        FINDINGS,
        key=lambda f: {
            "HIGH": 0,
            "MEDIUM": 1,
            "LOW": 2,
        }.get(f["severity"], 3)
    )

    table = Table(
        box=box.ROUNDED,
        border_style="yellow",
        header_style="bold yellow",
        expand=True,
    )

    table.add_column(
        "Risk",
        justify="center",
        width=10
    )

    table.add_column(
        "Packet",
        justify="center",
        width=8
    )

    table.add_column(
        "Finding"
    )

    for finding in ordered:

        severity = finding["severity"]

        table.add_row(
            Text(
                severity,
                style=severity_style(
                    severity
                )
            ),

            str(finding["packet"]),

            finding["reason"],
        )

    console.print(table)


def print_conversations():

    table = Table(
        title="Top Conversations",
        box=box.ROUNDED,
        border_style="magenta",
        header_style="bold magenta",
        expand=True,
    )

    table.add_column(
        "Source",
        style="white"
    )

    table.add_column(
        "Destination",
        style="white"
    )

    table.add_column(
        "Protocol",
        justify="center"
    )

    table.add_column(
        "Packets",
        justify="right"
    )

    for flow, count in FLOWS.most_common(10):

        src, dst, proto, sport, dport = flow

        source = (
            f"{src}:{sport}"
            if sport
            else src
        )

        destination = (
            f"{dst}:{dport}"
            if dport
            else dst
        )

        table.add_row(
            source,
            destination,

            Text(
                proto,
                style=f"bold {protocol_style(proto)}"
            ),

            str(count),
        )

    console.print(table)


def print_final_summary():

    console.print()

    console.print(
        Panel(
            Text(
                "✓ ANALYSIS COMPLETE",
                style="bold green",
                justify="center",
            ),
            border_style="green",
            box=box.DOUBLE,
        )
    )


# ============================================================
# EXPORT
# ============================================================

def redacted_report(summaries):

    clean = []

    for item in summaries:

        clean.append({

            "time": item["time"],

            "source":
                short_id(item["source"]),

            "destination":
                short_id(item["destination"]),

            "protocol":
                item["protocol"],

            "source_port":
                item["source_port"],

            "destination_port":
                item["destination_port"],

            "bytes":
                item["bytes"],

            "summary":
                f"{short_id(item['source'])} "
                f"sent {item['bytes']} bytes to "
                f"{short_id(item['destination'])}: "
                f"{item['protocol']} traffic",
        })

    findings = [

        {
            **finding,

            "source":
                short_id(finding["source"]),

            "destination":
                short_id(finding["destination"]),
        }

        for finding in FINDINGS
    ]

    findings.sort(
        key=lambda f:
            {
                "HIGH": 0,
                "MEDIUM": 1,
                "LOW": 2,
            }.get(
                f["severity"],
                3
            )
    )

    return {

        "generated_at":
            datetime.now(
                timezone.utc
            ).isoformat(),

        "privacy_note":
            "IP addresses are pseudonymized; "
            "packet payloads, DNS names, and HTTP "
            "paths are not exported.",

        "packet_count":
            len(clean),

        "protocols":
            dict(PROTOCOLS),

        "conversations": [

            {
                "source":
                    short_id(flow[0]),

                "destination":
                    short_id(flow[1]),

                "protocol":
                    flow[2],

                "source_port":
                    flow[3],

                "destination_port":
                    flow[4],

                "packets":
                    count,
            }

            for flow, count
            in FLOWS.most_common()
        ],

        "findings":
            findings,

        "packets":
            clean,
    }


# ============================================================
# MAIN
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=
            "Capture and explain network metadata."
    )

    parser.add_argument(
        "--read-pcap",
        help=
            "analyze a saved PCAP file "
            "instead of live capture"
    )

    parser.add_argument(
        "--interface",
        help=
            "network interface to capture on"
    )

    parser.add_argument(
        "--filter",
        dest="capture_filter",
        help=
            "optional BPF filter, "
            "e.g. 'tcp port 80'"
    )

    parser.add_argument(
        "--count",
        type=int,
        default=100,
        help=
            "maximum packets to capture "
            "(default: 100)"
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help=
            "capture time limit in seconds "
            "(default: 30)"
    )

    parser.add_argument(
        "--save-pcap",
        help=
            "optional path to save captured packets"
    )

    parser.add_argument(
        "--export",
        help=
            "optional redacted report path "
            "(.json or .csv)"
    )

    args = parser.parse_args()

    if args.count < 1 or args.timeout < 1:

        parser.error(
            "--count and --timeout "
            "must be positive"
        )

    # --------------------------------------------------------
    # START UI
    # --------------------------------------------------------

    clear_screen()

    mode = (
        "PCAP ANALYSIS"
        if args.read_pcap
        else "LIVE CAPTURE"
    )

    print_banner(mode)

    # --------------------------------------------------------
    # CAPTURE
    # --------------------------------------------------------

    try:

        if args.read_pcap:

            console.print(
                Panel(
                    f"[bold cyan]Reading:[/bold cyan] "
                    f"{args.read_pcap}",
                    border_style="cyan",
                )
            )

            PACKETS.extend(
                rdpcap(args.read_pcap)
            )

        else:

            console.print(
                Panel(
                    f"[bold cyan]Packet limit:[/bold cyan] "
                    f"{args.count}\n"
                    f"[bold cyan]Timeout:[/bold cyan] "
                    f"{args.timeout} seconds",
                    border_style="cyan",
                )
            )

            PACKETS.extend(
                sniff(
                    iface=args.interface,
                    filter=args.capture_filter,
                    count=args.count,
                    timeout=args.timeout,
                    store=True,
                )
            )

    except PermissionError:

        parser.error(
            "Packet capture needs appropriate "
            "operating-system permissions."
        )

    except (OSError, ValueError) as exc:

        parser.error(
            f"Capture failed: {exc}"
        )

    # --------------------------------------------------------
    # ANALYZE
    # --------------------------------------------------------

    summaries = []

    console.print()

    console.print(
        Panel(
            "Analyzing packets...",
            border_style="bright_blue",
            style="bold cyan",
        )
    )

    for number, packet in enumerate(
        PACKETS,
        1
    ):

        summary = describe_packet(
            packet,
            number
        )

        if summary:

            summaries.append(summary)

            assess(summary)

    assess_capture_patterns(
        summaries
    )

    # --------------------------------------------------------
    # DISPLAY RESULTS
    # --------------------------------------------------------

    console.print()

    # Packet table
    packet_table = Table(
        title=f"Packets Analyzed — {len(summaries)}",
        box=box.SIMPLE_HEAVY,
        border_style="bright_blue",
        header_style="bold cyan",
        expand=True,
    )

    packet_table.add_column(
        "#",
        justify="right",
        width=5
    )

    packet_table.add_column(
        "Source"
    )

    packet_table.add_column(
        "Destination"
    )

    packet_table.add_column(
        "Protocol",
        justify="center"
    )

    packet_table.add_column(
        "Bytes",
        justify="right"
    )

    packet_table.add_column(
        "Information"
    )

    # Show first 100 packets
    for item in summaries[:100]:

        packet_table.add_row(

            str(item["number"]),

            item["source"],

            item["destination"],

            Text(
                item["protocol"],
                style=
                    f"bold "
                    f"{protocol_style(item['protocol'])}"
            ),

            f"{item['bytes']:,}",

            item["details"],
        )

    console.print(packet_table)

    # --------------------------------------------------------
    # REPORT
    # --------------------------------------------------------

    console.print()

    print_traffic_summary(
        summaries
    )

    console.print()

    print_findings()

    console.print()

    print_conversations()

    print_final_summary()

    # --------------------------------------------------------
    # SAVE PCAP
    # --------------------------------------------------------

    if args.save_pcap:

        wrpcap(
            args.save_pcap,
            PACKETS
        )

        console.print(
            Panel(
                f"[green]Raw capture saved:[/green] "
                f"{args.save_pcap}\n"
                "[yellow]Warning:[/yellow] "
                "Raw captures may contain sensitive "
                "packet data.",
                border_style="yellow",
            )
        )

    # --------------------------------------------------------
    # EXPORT
    # --------------------------------------------------------

    if args.export:

        report = redacted_report(
            summaries
        )

        path = Path(args.export)

        if path.suffix.lower() == ".csv":

            with path.open(
                "w",
                newline="",
                encoding="utf-8"
            ) as handle:

                rows = report["packets"]

                fieldnames = (
                    list(rows[0])
                    if rows
                    else [
                        "time",
                        "source",
                        "destination",
                        "protocol",
                        "source_port",
                        "destination_port",
                        "bytes",
                        "summary",
                    ]
                )

                writer = csv.DictWriter(
                    handle,
                    fieldnames=fieldnames
                )

                writer.writeheader()

                writer.writerows(rows)

            console.print(
                f"[green]✓ CSV report exported:[/green] "
                f"{path}"
            )

        else:

            path.write_text(
                json.dumps(
                    report,
                    indent=2
                ),
                encoding="utf-8"
            )

            console.print(
                f"[green]✓ JSON report exported:[/green] "
                f"{path}"
            )


if __name__ == "__main__":
    main()
