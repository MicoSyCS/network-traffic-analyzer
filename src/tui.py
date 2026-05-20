"""
tui.py
------
Live terminal dashboard for the network analyzer, built on `rich`.

Two-column layout with a header strip and a footer strip:

    ┌───────── status bar ─────────┐
    │ packets / alerts / uptime    │
    ├──────────────┬───────────────┤
    │ live packets │ recent alerts │
    │              │               │
    ├──────────────┴───────────────┤
    │ protocol breakdown + talkers │
    └──────────────────────────────┘

Threading model
---------------
The sniffer runs in a background daemon thread and writes into a shared
TUIState. The Live display runs on the main thread (`rich.Live` requires
it) and reads snapshots of that state on every refresh tick. A single
threading.Lock guards every read/write; alerts and packets are tiny so
contention is negligible.

Usage from main.py
------------------
    state = TUIState()
    sniffer = threading.Thread(
        target=start_capture,
        kwargs={"on_packet": lambda info, pkt: state.record_packet(info),
                "print_packets": False, ...},
        daemon=True,
    )
    sniffer.start()
    run_tui(state)   # blocks until user hits Ctrl+C
"""

import threading
import time
from collections import Counter, deque

from rich.align import Align
from rich.console import Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

import ipnames


# ---- color/style choices --------------------------------------------------
SEVERITY_STYLES = {
    "low":      "yellow",
    "medium":   "magenta",
    "high":     "bold red",
    "critical": "bold white on red",
}

PROTOCOL_STYLES = {
    "TCP":   "cyan",
    "UDP":   "magenta",
    "ICMP":  "yellow",
    "Other": "dim white",
}

ORG_STYLE = "dim italic"  # styling for the "(Cloudflare)" annotations

# ---- how much history to retain in memory --------------------------------
# Keep a generous buffer so a maximized/fullscreen terminal can show many
# rows. render_packets() trims to whatever actually fits on screen.
MAX_PACKET_ROWS = 500
MAX_ALERT_ROWS = 50


class TUIState:
    """
    Thread-safe shared state between the sniffer and the renderer.

    Writers (sniffer thread): record_packet, record_alert, mark_sniffer_stopped
    Readers (main thread):    snapshot()
    """

    def __init__(self,
                 max_packets: int = MAX_PACKET_ROWS,
                 max_alerts: int = MAX_ALERT_ROWS):
        self._lock = threading.Lock()
        self._packets: deque = deque(maxlen=max_packets)
        self._alerts: deque = deque(maxlen=max_alerts)
        self._talkers: Counter[str] = Counter()      # src IP → cumulative bytes
        self._protocols: Counter[str] = Counter()    # bucket → packet count
        self._total_packets: int = 0
        self._total_alerts: int = 0
        self._start_time: float = time.time()
        self._sniffer_alive: bool = True
        self._sniffer_error: str | None = None

    # ------------------- writers (called from sniffer thread) ------------

    def record_packet(self, info: dict) -> None:
        with self._lock:
            self._total_packets += 1
            self._packets.append(info)

            src = info.get("src")
            if src and src != "?":
                self._talkers[src] += info.get("length", 0) or 0

            proto = info.get("protocol", "Other")
            if proto not in ("TCP", "UDP", "ICMP"):
                proto = "Other"
            self._protocols[proto] += 1

    def record_alert(self, alert: dict) -> None:
        with self._lock:
            self._total_alerts += 1
            self._alerts.append(alert)

    def mark_sniffer_stopped(self, error: str | None = None) -> None:
        with self._lock:
            self._sniffer_alive = False
            self._sniffer_error = error

    # ------------------- reader (called from main/render thread) ---------

    def snapshot(self) -> dict:
        """Return a consistent point-in-time copy of all state for rendering."""
        with self._lock:
            return {
                "uptime":         time.time() - self._start_time,
                "packets":        list(self._packets),
                "alerts":         list(self._alerts),
                "total_packets":  self._total_packets,
                "total_alerts":   self._total_alerts,
                "top_talkers":    self._talkers.most_common(5),
                "protocols":      dict(self._protocols),
                "sniffer_alive":  self._sniffer_alive,
                "sniffer_error":  self._sniffer_error,
            }


# ---------------------------------------------------------------------------
# Rendering helpers — each returns a rich renderable for one layout slot.
# ---------------------------------------------------------------------------

def _format_uptime(seconds: float) -> str:
    s = int(seconds)
    h, rem = divmod(s, 3600)
    m, s = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


def _format_bytes(n: int) -> str:
    if n >= 1024 * 1024:
        return f"{n / (1024 * 1024):.1f} MB"
    if n >= 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n} B"


def render_header(snap: dict) -> Panel:
    if snap["sniffer_alive"]:
        status = "[green]● Running[/green]"
    elif snap["sniffer_error"]:
        status = f"[bold red]✗ Error[/bold red] [dim]({snap['sniffer_error']})[/dim]"
    else:
        status = "[yellow]○ Stopped[/yellow]"

    left = Text.from_markup(
        f"{status}     "
        f"Packets: [bold cyan]{snap['total_packets']:,}[/bold cyan]     "
        f"Alerts: [bold red]{snap['total_alerts']}[/bold red]     "
        f"Uptime: [bold]{_format_uptime(snap['uptime'])}[/bold]"
    )
    right = Text.from_markup("[dim](Ctrl+C to quit)[/dim]")

    # A single-row grid pins the hint to the right edge regardless of width.
    grid = Table.grid(expand=True, padding=(0, 1))
    grid.add_column(justify="left", ratio=1)
    grid.add_column(justify="right")
    grid.add_row(left, right)

    return Panel(grid, title="[bold]Network Analyzer[/bold]",
                 border_style="blue", padding=(0, 1))


def render_packets(snap: dict, max_rows: int | None = None) -> Panel:
    table = Table(expand=True, show_header=True, header_style="bold dim",
                  padding=(0, 1), box=None)
    table.add_column("Time", width=12, style="dim")
    table.add_column("Proto", width=5)
    table.add_column("Source", overflow="ellipsis", ratio=2)
    table.add_column("→", width=1, justify="center", style="dim")
    table.add_column("Destination", overflow="ellipsis", ratio=2)
    table.add_column("Org", overflow="ellipsis", ratio=1, style=ORG_STYLE)
    table.add_column("Bytes", width=9, justify="right", style="dim")

    packets = snap["packets"]
    if max_rows is not None and max_rows > 0:
        # Show only the most recent rows that fit on screen.
        packets = packets[-max_rows:]

    if not packets:
        table.add_row("", "", "[dim italic]waiting for packets…[/dim italic]",
                      "", "", "", "")
    else:
        for info in packets:
            proto = info.get("protocol", "?")
            style = PROTOCOL_STYLES.get(proto, "white")
            src_ip = info.get("src") or "?"
            dst_ip = info.get("dst") or "?"
            src = f"{src_ip}:{info['sport']}" if info.get("sport") is not None else src_ip
            dst = f"{dst_ip}:{info['dport']}" if info.get("dport") is not None else dst_ip

            # Identify the non-local endpoint for the Org column. Prefer the
            # destination unless it's local and the source isn't.
            org = ipnames.resolve(dst_ip) or ipnames.resolve(src_ip) or ""
            # Don't bother showing "Private LAN" — it's just noise here.
            if org in ("Private LAN", "Loopback", "Link-local"):
                org = ""

            ts = (info.get("timestamp") or "")[-12:]
            length = info.get("length", 0)

            table.add_row(
                ts,
                Text(proto, style=style),
                src,
                "→",
                dst,
                org,
                f"{length:,}",
            )

    return Panel(table, title="[bold]Live Packets[/bold]",
                 border_style="cyan", padding=(0, 1))


def render_alerts(snap: dict) -> Panel:
    alerts = snap["alerts"]
    if not alerts:
        return Panel(
            Align.center(Text("no alerts yet", style="dim italic"),
                         vertical="middle"),
            title="[bold]Alerts[/bold]",
            border_style="red",
        )

    chunks: list = []
    # Newest first — alerts are rarer and more important than packets.
    for alert in reversed(alerts):
        sev = (alert.get("severity") or "low").lower()
        style = SEVERITY_STYLES.get(sev, "white")
        icon = "⚠" if sev in ("high", "critical") else "◐"
        atype = (alert.get("type") or "?").upper()
        ts = (alert.get("timestamp") or "")[-8:]

        # source may be "ip" or "ip:port"; resolve the org from the bare IP.
        src = alert.get("source", "?")
        src_ip = src.rsplit(":", 1)[0] if ":" in src else src
        src_org = ipnames.resolve(src_ip)
        src_disp = f"{src} [{ORG_STYLE}]({src_org})[/{ORG_STYLE}]" if src_org else src

        dst = alert.get("destination_ip") or "—"
        dst_org = ipnames.resolve(dst) if dst != "—" else None
        dst_disp = f"{dst} [{ORG_STYLE}]({dst_org})[/{ORG_STYLE}]" if dst_org else dst

        msg = alert.get("message", "")  # full message, no truncation

        chunks.append(Text.from_markup(
            f"[{style}]{icon}  {sev.upper():<8} {atype:<14} {ts}[/{style}]"
        ))
        chunks.append(Text.from_markup(
            f"   [dim]src=[/dim]{src_disp}  [dim]dst=[/dim]{dst_disp}"
        ))
        # Let rich wrap the full description across lines as needed.
        chunks.append(Text.from_markup(f"   [dim]{msg}[/dim]"))
        chunks.append(Text(""))

    return Panel(Group(*chunks), title="[bold]Alerts[/bold]",
                 border_style="red", padding=(0, 1))


def render_footer(snap: dict) -> Panel:
    # ---- protocol breakdown with mini bars --------------------------------
    total = sum(snap["protocols"].values())
    if total > 0:
        bar_width = 18
        proto_renderables: list = [Text.from_markup("[bold]Protocols[/bold]")]
        for proto in ("TCP", "UDP", "ICMP", "Other"):
            count = snap["protocols"].get(proto, 0)
            pct = (count / total) * 100 if total else 0
            filled = int(round(pct / 100 * bar_width))
            bar = "█" * filled + "░" * (bar_width - filled)
            style = PROTOCOL_STYLES.get(proto, "white")
            proto_renderables.append(Text.from_markup(
                f"[{style}]{proto:<5}[/{style}] {bar} "
                f"[bold]{pct:>5.1f}%[/bold]  [dim]({count:,})[/dim]"
            ))
        proto_block = Group(*proto_renderables)
    else:
        proto_block = Text("no traffic yet", style="dim italic")

    # ---- top talkers as a horizontal bar graph ----------------------------
    talkers = snap["top_talkers"]
    if talkers:
        bar_width = 18
        max_bytes = max(b for _, b in talkers) or 1
        talker_renderables: list = [Text.from_markup("[bold]Top Talkers (by bytes)[/bold]")]
        for ip, b in talkers:
            filled = int(round((b / max_bytes) * bar_width))
            bar = "█" * filled + "░" * (bar_width - filled)
            org = ipnames.resolve(ip)
            label = f"{ip} [{ORG_STYLE}]({org})[/{ORG_STYLE}]" if org else ip
            talker_renderables.append(Text.from_markup(
                f"[magenta]{bar}[/magenta] [bold]{_format_bytes(b):>9}[/bold]  {label}"
            ))
        talker_block = Group(*talker_renderables)
    else:
        talker_block = Text("Top talkers: (none yet)", style="dim italic")

    # Two columns side by side: protocols on the left, talkers on the right.
    grid = Table.grid(expand=True, padding=(0, 2))
    grid.add_column(ratio=1)
    grid.add_column(ratio=1)
    grid.add_row(proto_block, talker_block)

    return Panel(
        grid,
        title="[bold]Traffic Stats[/bold]",
        border_style="green",
        padding=(0, 1),
    )


# ---------------------------------------------------------------------------
# Layout assembly + Live loop
# ---------------------------------------------------------------------------

def build_layout() -> Layout:
    layout = Layout(name="root")
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="main"),
        Layout(name="footer", size=8),
    )
    layout["main"].split_row(
        Layout(name="packets"),
        Layout(name="alerts"),
    )
    return layout


# Fixed vertical chrome around the packet rows: header(3) + footer(8) +
# packet panel borders/title(2) + table header row(1). Used to work out how
# many packet rows actually fit so a fullscreen window stays full.
_VERTICAL_CHROME = 3 + 8 + 2 + 1


def _packet_capacity(console_height: int) -> int:
    """How many packet rows fit given the current terminal height."""
    return max(5, console_height - _VERTICAL_CHROME)


def _refresh(layout: Layout, state: TUIState, packet_rows: int) -> None:
    snap = state.snapshot()
    layout["header"].update(render_header(snap))
    layout["packets"].update(render_packets(snap, max_rows=packet_rows))
    layout["alerts"].update(render_alerts(snap))
    layout["footer"].update(render_footer(snap))


def run_tui(state: TUIState, refresh_per_second: int = 4) -> None:
    """
    Run the live dashboard on the calling thread until Ctrl+C.

    The sniffer must already be running in another (daemon) thread that
    writes into `state`. This function blocks until the user interrupts.
    """
    layout = build_layout()

    # screen=True swaps to the alt screen buffer — clean exit on Ctrl+C
    # returns the terminal to its prior state without scrollback pollution.
    with Live(layout, refresh_per_second=refresh_per_second,
              screen=True, redirect_stderr=False) as live:
        # Initial paint using the live console's measured height.
        rows = _packet_capacity(live.console.size.height)
        _refresh(layout, state, rows)
        try:
            interval = 1.0 / refresh_per_second
            while True:
                # Re-measure each tick so resizing the window adjusts the
                # number of visible packet rows on the fly.
                rows = _packet_capacity(live.console.size.height)
                _refresh(layout, state, rows)
                time.sleep(interval)
        except KeyboardInterrupt:
            pass

    # After the Live context exits, surface any sniffer error to the user
    # (otherwise it'd be lost — we suppress stdout while the TUI is running).
    snap = state.snapshot()
    if snap["sniffer_error"]:
        print(f"\n[!] Sniffer thread exited with error: {snap['sniffer_error']}")


# ---------------------------------------------------------------------------
# Smoke test: feed synthetic data, render each panel ONCE to stdout, exit.
# Run with:  python tui.py
# Lets you visually verify layout & styling without a live capture.
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from rich.console import Console

    state = TUIState()

    # First, bulk-fill to build realistic top-talker / protocol stats.
    # Use real provider IPs so the org lookup and bar graph have content.
    for _ in range(2000):
        state.record_packet({"protocol": "TCP", "src": "104.29.157.64", "length": 1500})
    for _ in range(800):
        state.record_packet({"protocol": "TCP", "src": "162.159.130.234", "length": 1500})
    for _ in range(300):
        state.record_packet({"protocol": "UDP", "src": "8.8.8.8", "length": 100})
    for _ in range(150):
        state.record_packet({"protocol": "TCP", "src": "140.82.114.26", "length": 800})
    for _ in range(80):
        state.record_packet({"protocol": "TCP", "src": "10.16.98.107", "length": 600})

    sample_packets = [
        {"timestamp": "2026-05-19 13:42:01.234", "protocol": "TCP",
         "src": "10.16.98.107", "sport": 54221, "dst": "162.159.130.234", "dport": 443,
         "length": 1420},
        {"timestamp": "2026-05-19 13:42:01.456", "protocol": "UDP",
         "src": "10.16.98.107", "sport": 53000, "dst": "8.8.8.8", "dport": 53,
         "length": 68},
        {"timestamp": "2026-05-19 13:42:02.001", "protocol": "TCP",
         "src": "104.29.157.64", "sport": 443, "dst": "10.16.98.107", "dport": 54221,
         "length": 60},
        {"timestamp": "2026-05-19 13:42:02.789", "protocol": "ICMP",
         "src": "10.16.98.107", "dst": "8.8.8.8", "length": 84},
        {"timestamp": "2026-05-19 13:42:03.100", "protocol": "TCP",
         "src": "10.16.98.107", "sport": 49283, "dst": "140.82.114.26", "dport": 443,
         "length": 372},
    ]
    for p in sample_packets:
        state.record_packet(p)

    state.record_alert({
        "timestamp": "2026-05-19 13:42:05",
        "type": "port_scan", "severity": "medium",
        "source": "10.16.96.1",
        "message": "16 unique destination ports contacted in 60s (threshold=15)",
    })
    state.record_alert({
        "timestamp": "2026-05-19 13:42:08",
        "type": "dns_anomaly", "severity": "high",
        "source": "10.16.98.107", "destination_ip": "8.8.8.8",
        "message": "DNS query with 64-char domain name (threshold=50) — possible DNS tunneling",
    })

    snap = state.snapshot()
    console = Console()
    console.print(render_header(snap))
    console.print(render_packets(snap, max_rows=10))
    console.print(render_alerts(snap))
    console.print(render_footer(snap))