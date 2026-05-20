"""
logger.py
---------
Central alert sink for the network analyzer.

Receives alert dicts from any detector in detector.py and persists them to:
  * a SQLite database  (logs/alerts.db) — for queryable history
  * a plain text file  (logs/alerts.log) — for human-readable tailing
  * stdout (in red, via colorama) — for HIGH / CRITICAL severity only

Schema (alerts table):
    id              INTEGER PRIMARY KEY
    timestamp       TEXT     ISO-ish format, "YYYY-MM-DD HH:MM:SS"
    alert_type      TEXT     e.g. "port_scan", "dns_anomaly", "large_transfer"
    source_ip       TEXT     IP only (port stripped if present)
    destination_ip  TEXT     nullable — port-scan alerts have no single dest
    severity        TEXT     "low" | "medium" | "high" | "critical"
    description     TEXT     human-readable summary
    extra           TEXT     JSON blob of detector-specific fields

Thread safety
-------------
SQLite connections are opened with check_same_thread=False and serialized
through a single threading.Lock. Alerts are rare events, so contention is
effectively zero. The connection lives for the process lifetime.

Usage
-----
    from logger import AlertLogger
    logger = AlertLogger()
    alert = some_detector.observe(info, packet)
    if alert is not None:
        logger.log_alert(alert)

    # Querying history later:
    recent_high = logger.query(severity="high", limit=10)
    for row in recent_high:
        print(row)
"""

import json
import sqlite3
import threading
from datetime import datetime
from pathlib import Path

from colorama import Fore, Style, init as colorama_init


# autoreset=True so each colored print resets style automatically, sparing
# us from manually appending Style.RESET_ALL every time.
colorama_init(autoreset=True)


_DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "logs" / "alerts.db"
_DEFAULT_TXT_PATH = Path(__file__).resolve().parent.parent / "logs" / "alerts.log"


# Severities we explicitly recognize. Anything else is normalized to "low".
_SEVERITY_LEVELS = {"low", "medium", "high", "critical"}

# Color mapping for stdout output. Only high/critical actually get printed;
# the rest are listed for documentation / future use.
_SEVERITY_COLORS = {
    "low": Fore.YELLOW,
    "medium": Fore.MAGENTA,
    "high": Fore.RED + Style.BRIGHT,
    "critical": Fore.RED + Style.BRIGHT,
}

# Detector-specific keys we don't want stored twice (they already live in
# their own columns). Everything else from the alert dict goes into `extra`.
_TOP_LEVEL_KEYS = {
    "timestamp", "source", "type", "severity", "message",
    "destination", "destination_ip",
}


def _split_ip_port(value: str | None) -> tuple[str | None, int | None]:
    """
    Split "ip:port" or "[ipv6]:port" into (ip, port). Returns (value, None)
    if no port is present, or (None, None) for falsy input.

    IPv6 addresses contain colons, so we have to be careful: only the LAST
    colon separates port when the address isn't bracketed, and even that
    is ambiguous. We treat anything with >1 colon as a bare IPv6 address
    unless it's wrapped in [].
    """
    if not value:
        return None, None

    # Bracketed IPv6 with port: "[2001:db8::1]:443"
    if value.startswith("["):
        end = value.find("]")
        if end != -1:
            ip = value[1:end]
            rest = value[end + 1:]
            port = int(rest.lstrip(":")) if rest.startswith(":") else None
            return ip, port

    # Bare IPv6 (multiple colons, not bracketed)
    if value.count(":") > 1:
        return value, None

    # IPv4 with optional port
    if ":" in value:
        ip, port_str = value.rsplit(":", 1)
        try:
            return ip, int(port_str)
        except ValueError:
            return value, None

    return value, None


class AlertLogger:
    """
    Thread-safe alert sink.

    Public methods:
        log_alert(alert)        — persist + (maybe) print one alert
        query(...)              — read history back from SQLite
        close()                 — flush and close the DB connection
    """

    def __init__(self,
                 db_path: Path | str | None = None,
                 txt_path: Path | str | None = None):
        self.db_path = Path(db_path) if db_path else _DEFAULT_DB_PATH
        self.txt_path = Path(txt_path) if txt_path else _DEFAULT_TXT_PATH

        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.txt_path.parent.mkdir(parents=True, exist_ok=True)

        self._lock = threading.Lock()
        # check_same_thread=False is safe here because we serialize every
        # access through self._lock.
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp       TEXT NOT NULL,
                    alert_type      TEXT NOT NULL,
                    source_ip       TEXT NOT NULL,
                    destination_ip  TEXT,
                    severity        TEXT NOT NULL,
                    description     TEXT NOT NULL,
                    extra           TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_alerts_severity
                    ON alerts(severity);
                CREATE INDEX IF NOT EXISTS idx_alerts_timestamp
                    ON alerts(timestamp);
                CREATE INDEX IF NOT EXISTS idx_alerts_source
                    ON alerts(source_ip);
            """)
            self._conn.commit()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def log_alert(self, alert: dict) -> None:
        """Persist `alert` to SQLite + text file, and (if high-sev) print red."""
        if alert is None:
            return  # tolerant: callers can pass detector.observe() return value

        # Normalize fields.
        timestamp = alert.get("timestamp") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alert_type = alert.get("type", "unknown")
        severity = (alert.get("severity") or "low").lower()
        if severity not in _SEVERITY_LEVELS:
            severity = "low"
        description = alert.get("message", "")

        # `source` may be "ip" or "ip:port"; we keep just the IP for the column.
        source_ip, _ = _split_ip_port(alert.get("source"))
        # `destination_ip` is preferred; fall back to parsing `destination`.
        dest_ip = alert.get("destination_ip")
        if dest_ip is None:
            dest_ip, _ = _split_ip_port(alert.get("destination"))

        extra_dict = {k: v for k, v in alert.items() if k not in _TOP_LEVEL_KEYS}
        # `default=str` keeps the call total even if a detector slips in a
        # non-JSON-serializable value (e.g. datetime, set, bytes).
        extra_json = json.dumps(extra_dict, default=str) if extra_dict else None

        with self._lock:
            self._conn.execute(
                """INSERT INTO alerts
                   (timestamp, alert_type, source_ip, destination_ip,
                    severity, description, extra)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (timestamp, alert_type, source_ip, dest_ip,
                 severity, description, extra_json),
            )
            self._conn.commit()
            self._append_text_log(
                timestamp, alert_type, source_ip, dest_ip,
                severity, description, extra_json,
            )

        # Red console output for high/critical, AFTER persistence.
        # Done outside the lock — print is fine without it, and we don't
        # want any I/O blocking the next alert's DB write.
        if severity in ("high", "critical"):
            print_high_severity(
                timestamp, alert_type, source_ip, dest_ip,
                severity, description,
            )

    def _append_text_log(self, timestamp, alert_type, source_ip, dest_ip,
                         severity, description, extra_json) -> None:
        """Append one structured line to the text log. Caller holds the lock."""
        dst_field = dest_ip if dest_ip else "-"
        line = (
            f"{timestamp} | {severity.upper():<8} | {alert_type:<16} | "
            f"src={source_ip:<22} dst={dst_field:<22} | {description}"
        )
        if extra_json:
            line += f" | extra={extra_json}"
        with self.txt_path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")

    def query(self, severity: str | None = None,
              alert_type: str | None = None,
              source_ip: str | None = None,
              limit: int = 50) -> list[dict]:
        """
        Read alerts back from SQLite.

        All filter args are optional and AND-ed together. Returns newest-first.
        """
        sql = "SELECT * FROM alerts WHERE 1=1"
        params: list = []
        if severity:
            sql += " AND severity = ?"
            params.append(severity.lower())
        if alert_type:
            sql += " AND alert_type = ?"
            params.append(alert_type)
        if source_ip:
            sql += " AND source_ip = ?"
            params.append(source_ip)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(int(limit))

        with self._lock:
            cur = self._conn.execute(sql, params)
            cols = [c[0] for c in cur.description]
            rows = [dict(zip(cols, r)) for r in cur.fetchall()]
        return rows

    def count(self) -> int:
        with self._lock:
            cur = self._conn.execute("SELECT COUNT(*) FROM alerts")
            return cur.fetchone()[0]

    def close(self) -> None:
        with self._lock:
            self._conn.close()


# ----------------------------------------------------------------------
# Console helper — exposed at module level per the spec ("write a function
# to also print high-severity alerts to the console in red").
# ----------------------------------------------------------------------

def print_high_severity(timestamp, alert_type, source_ip, dest_ip,
                        severity, description) -> None:
    """Print one high-severity alert in red. No-op for lower severities."""
    sev = (severity or "").lower()
    if sev not in ("high", "critical"):
        return
    color = _SEVERITY_COLORS[sev]
    dst_field = f" dst={dest_ip}" if dest_ip else ""
    # Two-line block so it stands out from the packet stream.
    print(f"{color}╔══ ALERT [{sev.upper()}] {alert_type.upper()} ══ {timestamp}")
    print(f"{color}║  src={source_ip}{dst_field}")
    print(f"{color}║  {description}")
    print(f"{color}╚══")


# ----------------------------------------------------------------------
# Self-test: create a logger, fire one alert at each severity, query back.
# Run with:  python logger.py
# ----------------------------------------------------------------------

if __name__ == "__main__":
    import tempfile

    # Use temp files so the smoke test doesn't pollute logs/alerts.{db,log}.
    tmpdir = Path(tempfile.mkdtemp(prefix="alertlog_test_"))
    log = AlertLogger(
        db_path=tmpdir / "alerts.db",
        txt_path=tmpdir / "alerts.log",
    )

    print(f"Self-test: writing 4 alerts to {tmpdir} ...")
    fakes = [
        {
            "timestamp": "2026-05-19 12:00:00",
            "type": "port_scan", "severity": "medium",
            "source": "10.0.0.99",
            "message": "16 unique destination ports contacted in 60s",
            "unique_port_count": 16,
        },
        {
            "timestamp": "2026-05-19 12:00:01",
            "type": "dns_anomaly", "severity": "high",
            "source": "10.0.0.7",
            "destination_ip": "8.8.8.8",
            "message": "DNS query with 76-char domain name — possible tunneling",
            "domain": "a" * 60 + ".tunnel.evil.com",
        },
        {
            "timestamp": "2026-05-19 12:00:02",
            "type": "large_transfer", "severity": "low",
            "source": "10.0.0.5:50000",
            "destination": "203.0.113.9:443",
            "message": "TCP connection transferred 10.0 MB",
        },
        {
            "timestamp": "2026-05-19 12:00:03",
            "type": "test_event", "severity": "critical",
            "source": "10.0.0.1",
            "destination_ip": "10.0.0.2",
            "message": "Simulated critical event for self-test",
        },
    ]
    for a in fakes:
        log.log_alert(a)

    print(f"\nDB row count: {log.count()}  (expected 4)")
    print("\nAll alerts (newest first):")
    for row in log.query(limit=10):
        print(f"  [{row['severity']:<8}] {row['alert_type']:<14} "
              f"src={row['source_ip']} dst={row['destination_ip']}")
    print("\nOnly HIGH severity:")
    for row in log.query(severity="high"):
        print(f"  {row}")
    print(f"\nText log: {log.txt_path}")
    print(f"DB file:  {log.db_path}")
    log.close()