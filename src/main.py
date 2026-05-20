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

    TUI dashboard (live or pcap):
        sudo python main.py --tui
        python main.py --pcap path/to/capture.pcap --tui

Wiring:
    sniff() / pcap replay
        └─→ capture.parse_packet → info dict
                └─→ each detector in detector.py: observe(info, packet)
                        └─→ any returned alert is passed to AlertLogger
                             which writes SQLite + text + (high-sev only) red stdout
"""

import argparse
import sys
import threading

from capture import start_capture
from detector import PortScanDetector, DNSAnomalyDetector, LargeTransferDetector
from logger import AlertLogger
from tui import TUIState, run_tui


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

    parser.add_argument("--tui", action="store_true",
        help="Run inside a live terminal dashboard (rich-based). Sniffer "
             "moves to a background thread; stdout output is suppressed.")

    return parser.parse_args()


def build_pipeline(args):
    """
    Construct (detectors, alert_logger, on_packet).

    on_packet fans out to all detectors and forwards any returned alert
    to the AlertLogger. Returns ([], None, None) if detection is disabled.

    When `args.tui` is set, detectors and logger are configured to not
    print to stdout (the TUI renders everything itself).
    """
    if args.no_detect:
        return [], None, None

    quiet = args.tui  # TUI mode silences all stdout from the alert path

    # log_to_file=False so detectors only print to stdout; the AlertLogger
    # is the sole owner of file/DB output.
    detectors = [
        PortScanDetector(
            threshold=args.scan_threshold,
            window_seconds=args.scan_window,
            log_to_file=False,
            print_alerts=not quiet,
        ),
        DNSAnomalyDetector(
            max_length=args.dns_max_length,
            log_to_file=False,
            print_alerts=not quiet,
        ),
        LargeTransferDetector(
            threshold_bytes=int(args.transfer_threshold_mb * 1024 * 1024),
            log_to_file=False,
            print_alerts=not quiet,
        ),
    ]
    alert_logger = AlertLogger(print_alerts=not quiet)

    if not quiet:
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


def run_tui_mode(args, detectors, alert_logger):
    """
    Run live or pcap mode inside the TUI.

    The sniffer goes to a daemon thread and writes packets/alerts into a
    shared TUIState. The TUI runs on the main thread reading that state.
    """
    state = TUIState()

    def tui_on_packet(info, pkt):
        state.record_packet(info)
        for d in detectors:
            alert = d.observe(info, pkt)
            if alert is not None:
                if alert_logger is not None:
                    alert_logger.log_alert(alert)
                state.record_alert(alert)

    def sniffer_target():
        try:
            start_capture(
                interface=None if args.pcap else args.iface,
                offline=args.pcap,
                count=args.count,
                bpf_filter=args.bpf_filter,
                on_packet=tui_on_packet,
                print_packets=False,
            )
            state.mark_sniffer_stopped()
        except Exception as exc:
            state.mark_sniffer_stopped(error=f"{type(exc).__name__}: {exc}")

    sniffer = threading.Thread(target=sniffer_target, daemon=True)
    sniffer.start()
    run_tui(state)


def main():
    args = parse_args()

    detectors, alert_logger, on_packet = build_pipeline(args)

    try:
        if args.tui:
            run_tui_mode(args, detectors, alert_logger)
        elif args.pcap:
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