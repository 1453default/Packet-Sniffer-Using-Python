#!/usr/bin/env python3

from scapy.all import sniff, wrpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS
from scapy.layers.http import HTTPRequest
from colorama import Fore, Style, init
from rich.console import Console
from rich.table import Table
from datetime import datetime


init()
console = Console()


# Statistics
packet_count = 0
tcp_count = 0
udp_count = 0
icmp_count = 0

# Packet storage
captured_packets = []


def process_packet(packet):

    global packet_count
    global tcp_count
    global udp_count
    global icmp_count


    captured_packets.append(packet)


    if not packet.haslayer(IP):
        return


    packet_count += 1


    src = packet[IP].src
    dst = packet[IP].dst


    protocol = "OTHER"
    extra = ""


    if packet.haslayer(TCP):

        tcp_count += 1
        protocol = "TCP"

        extra = (
            f"{packet[TCP].sport}"
            f" -> "
            f"{packet[TCP].dport}"
        )


    elif packet.haslayer(UDP):

        udp_count += 1
        protocol = "UDP"

        extra = (
            f"{packet[UDP].sport}"
            f" -> "
            f"{packet[UDP].dport}"
        )


    elif packet.haslayer(ICMP):

        icmp_count += 1
        protocol = "ICMP"



    table = Table(
        title=f"Packet #{packet_count}"
    )


    table.add_column(
        "Field",
        style="cyan"
    )

    table.add_column(
        "Value",
        style="green"
    )


    table.add_row(
        "Time",
        str(datetime.now())
    )


    table.add_row(
        "Source IP",
        src
    )


    table.add_row(
        "Destination IP",
        dst
    )


    table.add_row(
        "Protocol",
        protocol
    )


    table.add_row(
        "Ports",
        extra
    )


    table.add_row(
        "Size",
        f"{len(packet)} bytes"
    )


    console.print(table)



    # DNS detection

    if packet.haslayer(DNS):

        print(
            Fore.YELLOW +
            "[DNS QUERY DETECTED]"
        )

        try:

            print(
                packet[DNS].qd.qname.decode()
            )

        except:

            pass



    # HTTP detection

    if packet.haslayer(HTTPRequest):

        print(
            Fore.GREEN +
            "[HTTP REQUEST]"
        )


        try:

            print(
                packet.Host.decode()
            )

            print(
                packet.Path.decode()
            )

        except:

            pass



def show_statistics():

    print("\n")
    print("="*50)
    print("FINAL STATISTICS")
    print("="*50)

    print(
        "Total Packets :",
        packet_count
    )

    print(
        "TCP Packets   :",
        tcp_count
    )

    print(
        "UDP Packets   :",
        udp_count
    )

    print(
        "ICMP Packets  :",
        icmp_count
    )


def main():

    print(
        Fore.GREEN +
        """
===================================
        PYTHON PACKET SNIFFER
===================================
        """
        +
        Style.RESET_ALL
    )


    print(
        "Starting capture..."
    )

    print(
        "Press CTRL+C to stop\n"
    )


    try:

        sniff(
            prn=process_packet,
            store=False
        )


    except KeyboardInterrupt:


        print(
            "\nStopping sniffer..."
        )


        show_statistics()


        save = input(
            "\nSave capture file? (y/n): "
        )


        if save.lower()=="y":

            wrpcap(
                "capture.pcap",
                captured_packets
            )

            print(
                "Saved as capture.pcap"
            )


        print(
            "Done."
        )



if __name__=="__main__":

    main()
