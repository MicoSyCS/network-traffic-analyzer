"""
detector.py
-----------
Behavioral detectors for the network analyzer.

Three detectors are provided, all emitting alerts in a uniform shape
(source, type, severity, timestamp, message, + detector-specific fields):

  * PortScanDetector       — source IPs hitting many unique dst ports fast
  * DNSAnomalyDetector     — DNS queries with abnormally long domain names
                             (a common DNS-tunneling fingerprint)
  * LargeTransferDetector  — TCP connections moving more than N bytes

Designed to plug into capture.start_capture() via its on_packet hook:

    from detector import PortScanDetector, DNSAnomalyDetector, LargeTransferDetector
    detectors = [PortScanDetector(), DNSAnomalyDetector(), LargeTransferDetector()]
    start_capture(on_packet=lambda info, pkt: [d.observe(info, pkt) for d in detectors])
"""

import logging
import time
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path

from scapy.all import DNS, DNSQR  # needed by DNSAnomalyDetector


def _build_logger(log_file: Path) -> logging.Logger:
    """Build a dedicated logger that appends alerts to log_file."""
    log_file.parent.mkdir(parents=True, exist_ok=True)
    # Use the absolute path in the logger name so multiple detectors
    # writing to different files don't share handlers.
    logger = logging.getLogger(f"detector::{log_file}")
    logger.setLevel(logging.INFO)
    if not logger.handlers:  # don't double-attach if re-instantiated
        handler = logging.FileHandler(log_file, encoding="utf-8")
        handler.setFormatter(
            logging.Formatter("%(asctime)s  %(levelname)s  %(message)s")
        )
        logger.addHandler(handler)
        logger.propagate = False
    return logger


# Default log file: <project_root>/logs/alerts.log
_DEFAULT_LOG_FILE = Path(__file__).resolve().parent.parent / "logs" / "alerts.log"


def _make_alert(*, source, alert_type, severity, message, ts, **extras) -> dict:
    """
    Build a uniformly-shaped alert dict.

    Required keys present on every alert from every detector:
        source     — the responsible IP / endpoint
        type       — short alert identifier (e.g. "port_scan")
        severity   — "low" | "medium" | "high" | "critical"
        timestamp  — formatted local time string
        message    — short human-readable summary

    Detector-specific fields are passed as kwargs and merged in.
    """
    return {
        "timestamp": datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S"),
        "source": source,
        "type": alert_type,
        "severity": severity,
        "message": message,
        **extras,
    }


class _BaseDetector:
    """Shared logger + console-emit behaviour for all detectors."""

    def __init__(self, log_file: Path | str | None = None,
                 log_to_file: bool = True,
                 print_alerts: bool = True):
        # log_to_file=False lets a central AlertLogger own the file/DB output
        # while detectors still print to stdout for immediate feedback.
        # print_alerts=False additionally silences stdout (used by the TUI).
        self.log_to_file = log_to_file
        self.print_alerts = print_alerts
        self.log_file = Path(log_file) if log_file else _DEFAULT_LOG_FILE
        self._logger = _build_logger(self.log_file) if log_to_file else None

    def _emit_alert(self, alert: dict, detail: str = "") -> dict:
        """Write alert to log file (if enabled) and surface it on stdout (if enabled)."""
        header = f"[{alert['type'].upper()}/{alert['severity'].upper()}] {alert['message']}"
        if self._logger is not None:
            log_line = f"{header} — source={alert['source']}"
            if detail:
                log_line = f"{log_line} — {detail}"
            self._logger.warning(log_line)

        if self.print_alerts:
            print(f"\n[!! ALERT {alert['timestamp']}] {header}")
            print(f"    source={alert['source']}")
            if detail:
                print(f"    {detail}")
            print()
        return alert


class PortScanDetector(_BaseDetector):
    """
    Sliding-window port scan detector.

    For each source IP we keep a deque of (timestamp, dst_port) entries.
    On every observation, entries older than `window_seconds` are evicted
    from the left of the deque (lazy, O(amortized 1)). If the count of
    *unique* destination ports remaining in the window exceeds `threshold`,
    the source IP is flagged.

    Alerts are deduplicated per source: once a source crosses the threshold
    it is marked as "alerted" and won't re-alert until its window drops back
    below threshold (and could then trigger again on a new burst).
    """

    def __init__(
        self,
        threshold: int = 15,
        window_seconds: int = 60,
        log_file: Path | str | None = None,
        log_to_file: bool = True,
        print_alerts: bool = True,
    ):
        super().__init__(log_file, log_to_file=log_to_file,
                         print_alerts=print_alerts)
        self.threshold = threshold
        self.window_seconds = window_seconds

        # source_ip -> deque[(ts_float, dport_int)]
        self._activity: dict[str, deque] = defaultdict(deque)
        # source IPs currently in alerted state (alert suppression)
        self._alerted: set[str] = set()

    def observe(self, info: dict, packet=None, ts: float | None = None) -> dict | None:
        """
        Process one packet's parsed info dict (from capture.parse_packet).

        `packet` is accepted for interface uniformity with other detectors
        but unused here. Returns an alert dict on trigger, else None.
        """
        dport = info.get("dport")
        if dport is None:
            return None  # no port → not relevant to port-scan detection

        src = info["src"]
        now = ts if ts is not None else time.time()

        # 1) Record this contact.
        activity = self._activity[src]
        activity.append((now, dport))

        # 2) Evict entries that have fallen out of the window.
        cutoff = now - self.window_seconds
        while activity and activity[0][0] < cutoff:
            activity.popleft()

        # 3) Count unique destination ports remaining in the window.
        unique_ports = {port for _, port in activity}

        if len(unique_ports) > self.threshold:
            if src not in self._alerted:
                self._alerted.add(src)
                return self._fire_alert(src, unique_ports, now)
        else:
            # Source has cooled off; re-arm so a future burst can trigger again.
            self._alerted.discard(src)

        return None

    def _fire_alert(self, src: str, unique_ports: set, ts: float) -> dict:
        alert = _make_alert(
            source=src,
            alert_type="port_scan",
            severity="medium",
            message=(
                f"{len(unique_ports)} unique destination ports contacted in "
                f"{self.window_seconds}s (threshold={self.threshold})"
            ),
            ts=ts,
            unique_ports=sorted(unique_ports),
            unique_port_count=len(unique_ports),
            window_seconds=self.window_seconds,
            threshold=self.threshold,
        )
        return self._emit_alert(alert, detail=f"ports={sorted(unique_ports)[:10]}{'...' if len(unique_ports) > 10 else ''}")

    def stats(self) -> dict:
        """Return current per-source activity counts (useful for debugging)."""
        return {src: len({p for _, p in dq}) for src, dq in self._activity.items()}


# ---------------------------------------------------------------------------
# DNS anomaly detector
# ---------------------------------------------------------------------------

class DNSAnomalyDetector(_BaseDetector):
    """
    Flag DNS queries whose queried domain name exceeds `max_length` chars.

    DNS tunneling tools (iodine, dnscat2, ...) encode exfil data into
    subdomain labels, producing query names like:

        aGVsbG8gd29ybGQgZGF0YQo.tunnel.attacker.com

    Legitimate domains are almost always short. A query name longer than
    ~50 chars is a strong tunneling signal. We dedupe per (src, domain)
    so a flood of identical queries only alerts once.

    Note: encrypted DNS (DoT/DoH/DoQ) is opaque to this detector by design.
    """

    def __init__(self, max_length: int = 50,
                 log_file: Path | str | None = None,
                 log_to_file: bool = True,
                 print_alerts: bool = True):
        super().__init__(log_file, log_to_file=log_to_file,
                         print_alerts=print_alerts)
        self.max_length = max_length
        self._seen: set[tuple[str, str]] = set()  # (src, domain) dedup

    def observe(self, info: dict, packet=None, ts: float | None = None) -> dict | None:
        # Needs the raw packet to read the DNS layer; ignore everything else.
        if packet is None or not packet.haslayer(DNS):
            return None
        dns = packet[DNS]

        # Only inspect QUERIES (qr=0), not responses, and require a question.
        if dns.qr != 0 or dns.qdcount == 0:
            return None

        try:
            qname_bytes = dns[DNSQR].qname
            qname = qname_bytes.decode("ascii", errors="replace").rstrip(".")
        except Exception:
            return None  # malformed DNS, ignore

        if len(qname) <= self.max_length:
            return None

        src = info.get("src", "?")
        key = (src, qname)
        if key in self._seen:
            return None
        self._seen.add(key)

        now = ts if ts is not None else time.time()
        alert = _make_alert(
            source=src,
            alert_type="dns_anomaly",
            severity="high",  # long DNS names are very unusual in normal traffic
            message=(
                f"DNS query with {len(qname)}-char domain name "
                f"(threshold={self.max_length}) — possible DNS tunneling"
            ),
            ts=now,
            destination_ip=info.get("dst"),  # the resolver being queried
            domain=qname,
            domain_length=len(qname),
            threshold=self.max_length,
        )
        # Truncate the domain in detail for sanity; full name is in the dict.
        shown = qname if len(qname) <= 80 else qname[:77] + "..."
        return self._emit_alert(alert, detail=f"domain={shown!r}")


# ---------------------------------------------------------------------------
# Large transfer detector
# ---------------------------------------------------------------------------

class LargeTransferDetector(_BaseDetector):
    """
    Flag TCP connections whose cumulative byte count exceeds `threshold_bytes`.

    A "connection" is identified by the unordered pair of endpoints
    {(ip_a, port_a), (ip_b, port_b)}, so client→server and server→client
    packets accumulate toward the same total.

    The `source` field in the emitted alert is whichever endpoint sent the
    first packet we observed for that flow — usually the client/initiator.

    Severity scales with size:
        > threshold     → "low"
        > 10× threshold → "medium"
        > 100× threshold→ "high"

    Note: connection state is retained indefinitely. For long-running
    captures with many short connections you may want to add FIN/RST
    cleanup or an LRU cap.
    """

    def __init__(
        self,
        threshold_bytes: int = 10 * 1024 * 1024,  # 10 MB
        log_file: Path | str | None = None,
        log_to_file: bool = True,
        print_alerts: bool = True,
    ):
        super().__init__(log_file, log_to_file=log_to_file,
                         print_alerts=print_alerts)
        self.threshold_bytes = threshold_bytes
        # connection_key -> {"bytes": int, "source": "ip:port",
        #                    "destination": "ip:port", "alerted": bool}
        self._connections: dict[tuple, dict] = {}

    @staticmethod
    def _connection_key(src, sport, dst, dport):
        """Direction-independent key for a TCP flow."""
        return tuple(sorted([(src, sport), (dst, dport)]))

    def _severity_for(self, total_bytes: int) -> str:
        if total_bytes > 100 * self.threshold_bytes:
            return "high"
        if total_bytes > 10 * self.threshold_bytes:
            return "medium"
        return "low"

    def observe(self, info: dict, packet=None, ts: float | None = None) -> dict | None:
        if info.get("protocol") != "TCP":
            return None

        src, sport = info.get("src"), info.get("sport")
        dst, dport = info.get("dst"), info.get("dport")
        if sport is None or dport is None:
            return None

        key = self._connection_key(src, sport, dst, dport)
        conn = self._connections.get(key)
        if conn is None:
            # First-seen direction defines who the "source" of the flow is.
            conn = {
                "bytes": 0,
                "source": f"{src}:{sport}",
                "destination": f"{dst}:{dport}",
                "alerted": False,
            }
            self._connections[key] = conn

        conn["bytes"] += info.get("length", 0)

        if conn["bytes"] > self.threshold_bytes and not conn["alerted"]:
            conn["alerted"] = True
            now = ts if ts is not None else time.time()
            mb = conn["bytes"] / (1024 * 1024)
            threshold_mb = self.threshold_bytes / (1024 * 1024)
            alert = _make_alert(
                source=conn["source"],
                alert_type="large_transfer",
                severity=self._severity_for(conn["bytes"]),
                message=(
                    f"TCP connection transferred {mb:.1f} MB "
                    f"(threshold={threshold_mb:.0f} MB)"
                ),
                ts=now,
                destination=conn["destination"],
                destination_ip=conn["destination"].rsplit(":", 1)[0],
                bytes_transferred=conn["bytes"],
                threshold_bytes=self.threshold_bytes,
            )
            return self._emit_alert(
                alert,
                detail=f"flow={conn['source']} ↔ {conn['destination']}  bytes={conn['bytes']:,}",
            )
        return None

    def stats(self) -> dict:
        """Return {flow_key: bytes_transferred} for current connections."""
        return {k: v["bytes"] for k, v in self._connections.items()}


# ---------------------------------------------------------------------------
# Self-test: simulate a scan to confirm the detector triggers correctly.
# Run with:  python detector.py
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    from scapy.all import IP, UDP

    print("Self-test 1: simulating a 25-port scan from 10.0.0.99 ...")
    psd = PortScanDetector(threshold=15, window_seconds=60)
    base_ts = time.time()
    for i, port in enumerate(range(1000, 1025)):
        psd.observe(
            {"src": "10.0.0.99", "dport": port, "protocol": "TCP"},
            ts=base_ts + i * 0.1,
        )
    # Benign source should not alert
    psd.observe({"src": "10.0.0.50", "dport": 443, "protocol": "TCP"}, ts=base_ts)

    print("Self-test 2: simulating DNS query with a 70-char domain ...")
    dad = DNSAnomalyDetector(max_length=50)
    long_domain = "a" * 60 + ".tunnel.evil.com"  # 76 chars total
    short_pkt = (
        IP(src="10.0.0.7", dst="8.8.8.8") / UDP(sport=44444, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="google.com"))
    )
    long_pkt = (
        IP(src="10.0.0.7", dst="8.8.8.8") / UDP(sport=44444, dport=53)
        / DNS(rd=1, qd=DNSQR(qname=long_domain))
    )
    dad.observe({"src": "10.0.0.7", "dport": 53, "protocol": "UDP"}, packet=short_pkt, ts=base_ts)
    dad.observe({"src": "10.0.0.7", "dport": 53, "protocol": "UDP"}, packet=long_pkt, ts=base_ts)

    print("Self-test 3: simulating a 12 MB TCP transfer ...")
    ltd = LargeTransferDetector(threshold_bytes=10 * 1024 * 1024)
    # 12 MB total, 1500B per packet → ~8400 packets. Alternate directions.
    info_a = {"protocol": "TCP", "src": "10.0.0.5", "sport": 50000,
              "dst": "203.0.113.9", "dport": 443, "length": 1500}
    info_b = {"protocol": "TCP", "src": "203.0.113.9", "sport": 443,
              "dst": "10.0.0.5", "dport": 50000, "length": 1500}
    target = 12 * 1024 * 1024
    sent = 0
    while sent < target:
        ltd.observe(info_a, ts=base_ts)
        ltd.observe(info_b, ts=base_ts)
        sent += 3000

    print(f"\n→ alert log written to: {psd.log_file}")