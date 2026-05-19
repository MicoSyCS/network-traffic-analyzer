"""
main.py
-------
Entry point for the network traffic analyzer.

Usage examples:
    sudo python main.py
    sudo python main.py --iface eth0 --count 20
    sudo python main.py --filter "tcp port 443"
"""

import argparse
import sys

from capture import start_capture


def parse_args():
    parser = argparse.ArgumentParser(
        description="Simple network traffic analyzer built on Scapy."
    )
    parser.add_argument(
        "-i", "--iface",
        default=None,
        help="Network interface to sniff on (default: Scapy's default).",
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=0,
        help="Number of packets to capture (0 = unlimited, default).",
    )
    parser.add_argument(
        "-f", "--filter",
        dest="bpf_filter",
        default=None,
        help='BPF filter, e.g. "tcp", "udp port 53", "host 1.1.1.1".',
    )
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        start_capture(
            interface=args.iface,
            count=args.count,
            bpf_filter=args.bpf_filter,
        )
    except PermissionError:
        print("[!] Permission denied. Try running with sudo / as Administrator.")
        sys.exit(1)~
    except KeyboardInterrupt:
        print("\n[+] Capture stopped by user.")
        sys.exit(0)


if __name__ == "__main__":
    main()