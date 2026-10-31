#!/usr/bin/env python3
"""
CodeAlpha Cyber Security Internship - Task 1: Basic Network Sniffer
A beginner-friendly packet sniffer built using Python and Scapy.
"""

import argparse
import sys
import time
from collections import Counter
from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP, Raw

# Global counters and storage for captured packets
protocol_stats = Counter()
captured_packets = []


def analyze_packet(packet):
    """
    Callback function executed for every packet captured by Scapy.
    Extracts key fields from IP, TCP, UDP, and ICMP headers and logs them.
    """
    global captured_packets, protocol_stats

    # Filter for IP layer packets (IPv4)
    if IP in packet:
        protocol_stats["Total"] += 1
        
        # Extract IP header details
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Default values for transport layer protocols
        protocol_name = "Other IP"
        src_port = "N/A"
        dst_port = "N/A"

        # Determine transport protocol and extract port numbers
        if TCP in packet:
            protocol_name = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            protocol_stats["TCP"] += 1
        elif UDP in packet:
            protocol_name = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol_stats["UDP"] += 1
        elif ICMP in packet:
            protocol_name = "ICMP"
            protocol_stats["ICMP"] += 1
        else:
            protocol_stats["Other"] += 1

        # Calculate payload size (data carried inside Raw layer if present)
        payload_size = len(packet[Raw].load) if Raw in packet else 0
        
        # Human-readable timestamp
        timestamp = time.strftime("%H:%M:%S", time.localtime(packet.time))

        # Formatted console output for each packet
        print(
            f"[{timestamp}] {protocol_name:<5} | "
            f"{src_ip}:{src_port:<5} -> {dst_ip}:{dst_port:<5} | "
            f"Payload: {payload_size} bytes"
        )

        # Append packet to list for PCAP saving
        captured_packets.append(packet)


def print_summary():
    """Displays packet count and protocol statistics summary."""
    print("\n" + "=" * 55)
    print("             PACKET CAPTURE SUMMARY STATISTICS            ")
    print("=" * 55)
    print(f" Total IP Packets Captured : {protocol_stats['Total']}")
    print("-" * 55)
    print(f"  - TCP Packets             : {protocol_stats['TCP']}")
    print(f"  - UDP Packets             : {protocol_stats['UDP']}")
    print(f"  - ICMP Packets            : {protocol_stats['ICMP']}")
    print(f"  - Other IP Protocols      : {protocol_stats['Other']}")
    print("=" * 55)


def main():
    # Setup Command-Line Arguments
    parser = argparse.ArgumentParser(
        description="CodeAlpha Task 1: Basic Network Packet Sniffer"
    )
    parser.add_argument(
        "-i", "--interface",
        type=str,
        default=None,
        help="Network interface to sniff on (e.g., eth0, wlan0, Ethernet). Default: all active."
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=0,
        help="Number of packets to capture (0 = capture until stopped with Ctrl+C). Default: 0."
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default="capture.pcap",
        help="Output filename for Wireshark analysis (.pcap). Default: capture.pcap."
    )

    args = parser.parse_args()

    # Informational display before packet capture begins
    print("[*] Starting Basic Network Sniffer...")
    if args.interface:
        print(f"[*] Interface     : {args.interface}")
    else:
        print("[*] Interface     : Default system interface")
    print(f"[*] Packet Target : {'Unlimited (Press Ctrl+C to stop)' if args.count == 0 else args.count}")
    print(f"[*] Output PCAP   : {args.output}")
    print("-" * 75)

    try:
        # Start sniffing network packets using Scapy
        sniff(
            iface=args.interface,
            prn=analyze_packet,
            count=args.count,
            store=False  # Avoid memory leaks; packets stored manually in captured_packets list
        )

    except KeyboardInterrupt:
        print("\n[*] Capture stopped by user (Ctrl+C).")
    except PermissionError:
        print("\n[!] Error: Root/Administrator permissions required.")
        print("    Run with elevated privileges:")
        print("    - Linux/macOS : sudo python3 sniffer.py")
        print("    - Windows     : Run Command Prompt / PowerShell as Administrator")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Unexpected error occurred: {e}")
        sys.exit(1)

    finally:
        # Display capture metrics
        print_summary()

        # Export captured packets to .pcap file
        if captured_packets:
            try:
                wrpcap(args.output, captured_packets)
                print(f"[*] Packets successfully saved to '{args.output}' for Wireshark analysis.")
            except Exception as e:
                print(f"[!] Failed to write PCAP file: {e}")
        else:
            print("[*] No IP packets were captured to save.")


if __name__ == "__main__":
    main()
