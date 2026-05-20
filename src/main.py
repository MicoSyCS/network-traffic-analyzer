"""
main.py
-------
Entry point for the network traffic analyzer.

Modes:
    Live capture (default):
        sudo python main.py
        sudo python main.py --iface eth0 --count 100
        sudo python main.py --filter "tcp port 443"

    Pcap replay:
        python main.py --pcap path/to/capture.pcap

Wiring:
    sniff() / pcap replay
        └─→ capture.parse_packet → info dict
                └─→ each detector in detector.py: observe(info, packet)
                        └─→ any returned alert is passed to AlertLogger
                             which writes SQLite + text + (high-sev only) red stdout
"""

import argparse
import sys

from capture import start_capture
from detector import PortScanDetector, DNSAnomalyDetector, LargeTransferDetector
from logger import AlertLogger


def parse_args():
    parser = argparse.ArgumentParser(
        description="Network traffic analyzer with detection and logging."
    )

    # --- Source selection: either --pcap or live (the default) ---
    src = parser.add_mutually_exclusive_group()
    src.add_argument(
        "--pcap",
        metavar="FILE",
        default=None,
        help="Analyze a saved .pcap/.pcapng file instead of live capture. "
             "Mutually exclusive with --iface.",
    )
    src.add_argument(
        "-i", "--iface",
        default=None,
        help="Network interface to sniff on (default: Scapy's default).",
    )

    parser.add_argument(
        "-c", "--count",
        type=int,
        default=0,
        help="Number of packets to capture/replay (0 = unlimited, default).",
    )
    parser.add_argument(
        "-f", "--filter",
        dest="bpf_filter",
        default=None,
        help='BPF filter, e.g. "tcp", "udp port 53", "host 1.1.1.1".',
    )

    # --- Detector tuning ---
    parser.add_argument("--scan-threshold", type=int, default=15,
        help="Unique destination ports / source IP that triggers a port-scan alert.")
    parser.add_argument("--scan-window", type=int, default=60,
        help="Sliding window seconds for port-scan detection.")
    parser.add_argument("--dns-max-length", type=int, default=50,
        help="Max acceptable DNS query name length.")
    parser.add_argument("--transfer-threshold-mb", type=float, default=10,
        help="Per-TCP-connection byte threshold (MB) for large-transfer alerts.")
    parser.add_argument("--no-detect", action="store_true",
        help="Disable all detectors (just print packets).")

    return parser.parse_args()


def build_pipeline(args):
    """
    Construct the (detectors, alert_logger, on_packet) tuple.

    on_packet is the per-packet callback that fans out to all detectors
    and forwards any returned alerts to the AlertLogger. Returns None
    for on_packet if detection is disabled.
    """
    if args.no_detect:
        return [], None, None

    # log_to_file=False so detectors only print to stdout; the AlertLogger
    # is the sole owner of file/DB output.
    detectors = [
        PortScanDetector(
            threshold=args.scan_threshold,
            window_seconds=args.scan_window,
            log_to_file=False,
        ),
        DNSAnomalyDetector(
            max_length=args.dns_max_length,
            log_to_file=False,
        ),
        LargeTransferDetector(
            threshold_bytes=int(args.transfer_threshold_mb * 1024 * 1024),
            log_to_file=False,
        ),
    ]
    alert_logger = AlertLogger()

    print(f"[+] Detectors enabled:")
    print(f"      port_scan       >{args.scan_threshold} ports / {args.scan_window}s")
    print(f"      dns_anomaly     domain length > {args.dns_max_length}")
    print(f"      large_transfer  TCP flow > {args.transfer_threshold_mb} MB")
    print(f"[+] Alerts → {alert_logger.db_path}  &  {alert_logger.txt_path}")

    def on_packet(info, pkt):
        for d in detectors:
            alert = d.observe(info, pkt)
            if alert is not None:
                alert_logger.log_alert(alert)

    return detectors, alert_logger, on_packet


def run_live(args, on_packet):
    """Live capture on a real interface."""
    start_capture(
        interface=args.iface,
        count=args.count,
        bpf_filter=args.bpf_filter,
        on_packet=on_packet,
    )


def run_pcap(args, on_packet):
    """Replay a saved pcap file through the same pipeline."""
    print(f"[+] Replaying pcap: {args.pcap}")
    start_capture(
        offline=args.pcap,
        count=args.count,
        bpf_filter=args.bpf_filter,
        on_packet=on_packet,
    )
    print("[+] Pcap replay complete.")


def main():
    args = parse_args()

    _, alert_logger, on_packet = build_pipeline(args)

    try:
        if args.pcap:
            run_pcap(args, on_packet)
        else:
            run_live(args, on_packet)
    except FileNotFoundError as exc:
        print(f"[!] File not found: {exc}")
        sys.exit(1)
    except PermissionError:
        print("[!] Permission denied. Try running with sudo / as Administrator.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[+] Stopped by user.")
    finally:
        if alert_logger is not None:
            alert_logger.close()


if __name__ == "__main__":
    main()