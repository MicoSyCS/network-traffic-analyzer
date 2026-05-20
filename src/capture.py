"""
capture.py
-----------
Live packet capture and parsing using Scapy.

For every sniffed packet we extract:
  - timestamp, source IP, destination IP, protocol, total length
  - TCP: source/destination ports and flag names (SYN, ACK, FIN, ...)
  - UDP: source/destination ports and payload length

Each packet is printed as one clean, labeled line.
"""

from datetime import datetime
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP


# Map common IP protocol numbers to human-readable names.
# Scapy gives us packet[IP].proto as an integer; this makes the output friendlier.
PROTO_NAMES = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    132: "SCTP",
}


# Scapy stringifies TCP flags compactly: "SA" for SYN+ACK, "FPA" for FIN+PSH+ACK, etc.
# This map turns each letter back into the full mnemonic for readable output.
TCP_FLAG_NAMES = {
    "F": "FIN",
    "S": "SYN",
    "R": "RST",
    "P": "PSH",
    "A": "ACK",
    "U": "URG",
    "E": "ECE",
    "C": "CWR",
    "N": "NS",
}


def _parse_tcp_flags(flags) -> list:
    """Return the list of human-readable TCP flag names that are set."""
    return [TCP_FLAG_NAMES[c] for c in str(flags) if c in TCP_FLAG_NAMES]


def _resolve_protocol(packet) -> str:
    """Return a friendly protocol name for the packet."""
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"
    if packet.haslayer(ARP):
        return "ARP"
    if packet.haslayer(IP):
        return PROTO_NAMES.get(packet[IP].proto, f"IP/{packet[IP].proto}")
    if packet.haslayer(IPv6):
        return PROTO_NAMES.get(packet[IPv6].nh, f"IPv6/{packet[IPv6].nh}")
    return packet.name  # fallback to the topmost layer name


def _extract_addresses(packet):
    """Return (src, dst) addresses for IPv4, IPv6, or ARP packets."""
    if packet.haslayer(IP):
        return packet[IP].src, packet[IP].dst
    if packet.haslayer(IPv6):
        return packet[IPv6].src, packet[IPv6].dst
    if packet.haslayer(ARP):
        return packet[ARP].psrc, packet[ARP].pdst
    return "?", "?"


def parse_packet(packet) -> dict:
    """
    Extract the fields we care about from a Scapy packet.

    Always returns: timestamp, src, dst, protocol, length.
    For TCP also: sport, dport, flags (list of names).
    For UDP also: sport, dport, payload_len (bytes of UDP data, header excluded).
    """
    src, dst = _extract_addresses(packet)
    info = {
        "timestamp": datetime.fromtimestamp(float(packet.time)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "src": src,
        "dst": dst,
        "protocol": _resolve_protocol(packet),
        "length": len(packet),
        "sport": None,
        "dport": None,
        "flags": None,
        "payload_len": None,
    }

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        info["sport"] = tcp.sport
        info["dport"] = tcp.dport
        info["flags"] = _parse_tcp_flags(tcp.flags)
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        info["sport"] = udp.sport
        info["dport"] = udp.dport
        # Prefer the on-wire UDP `len` field (header 8B + data); fall back to
        # measuring the payload directly when the field isn't populated
        # (e.g. on packets we constructed in-process rather than sniffed).
        if udp.len is not None:
            info["payload_len"] = max(0, int(udp.len) - 8)
        else:
            info["payload_len"] = len(bytes(udp.payload))

    return info


def _print_packet(info: dict) -> None:
    """Print a single packet in a clean, fixed-width format."""
    # Append :port to the address when we have one (TCP/UDP only).
    src = f"{info['src']}:{info['sport']}" if info["sport"] is not None else info["src"]
    dst = f"{info['dst']}:{info['dport']}" if info["dport"] is not None else info["dst"]

    # Per-protocol trailing info, clearly labeled.
    if info["flags"] is not None:
        extras = f"  flags=[{', '.join(info['flags']) or '-'}]"
    elif info["payload_len"] is not None:
        extras = f"  payload={info['payload_len']}B"
    else:
        extras = ""

    print(
        f"[{info['timestamp']}]  "
        f"{info['protocol']:<6}  "
        f"{src:<28} -> {dst:<28}  "
        f"len={info['length']:>5}B"
        f"{extras}"
    )


def _make_handler(on_packet=None):
    """Build the per-packet callback used by Scapy's sniff()."""

    def handler(packet):
        try:
            info = parse_packet(packet)
        except Exception as exc:  # don't let one bad packet stop the capture
            print(f"[!] Failed to parse packet: {exc}")
            return

        _print_packet(info)

        if on_packet is not None:
            on_packet(info, packet)

    return handler


def start_capture(interface=None, count=0, bpf_filter=None, on_packet=None,
                  offline=None):
    """
    Start a packet capture — either live (default) or by replaying a pcap.

    Args:
        interface:  Network interface to sniff on (None = Scapy default).
                    Ignored when `offline` is set.
        count:      Number of packets to capture (0 = unlimited).
        bpf_filter: Optional BPF filter string, e.g. "tcp port 80".
        on_packet:  Optional callback receiving (info_dict, raw_packet)
                    after each packet is printed. Useful for logging
                    or writing to /data.
        offline:    Path to a .pcap/.pcapng file. When set, packets are
                    read from the file instead of a live interface and
                    sniff() returns once the file is exhausted.

    Note: live sniffing usually requires root/admin privileges.
    """
    print("─" * 88)
    if offline:
        print(f"Replaying pcap     file={offline}  "
              f"count={'all' if count == 0 else count}  "
              f"filter={bpf_filter or 'none'}")
    else:
        print(f"Starting capture  iface={interface or 'default'}  "
              f"count={'∞' if count == 0 else count}  "
              f"filter={bpf_filter or 'none'}")
    print("─" * 88)

    sniff(
        iface=interface if not offline else None,
        offline=offline,
        prn=_make_handler(on_packet),
        count=count,
        filter=bpf_filter,
        store=False,  # don't keep packets in memory; we stream them
    )