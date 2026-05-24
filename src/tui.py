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
from keyboard import KeyReader


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
# Keep a large buffer so the user can pause and scroll back through history.
# render_packets() trims to whatever actually fits on screen (plus scroll).
MAX_PACKET_ROWS = 5000
MAX_ALERT_ROWS = 200


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
        # Rolling per-(second, ip) byte buckets so "top talkers" reflects
        # RECENT activity, not all-time totals. Without this, a few early
        # heavy-hitters dominate forever and the chart appears frozen.
        self._talker_window: deque = deque()  # (sec:int, ip:str, bytes:int)
        self._talker_window_seconds: int = 60
        self._protocols: Counter[str] = Counter()    # bucket → packet count
        self._total_packets: int = 0
        self._total_alerts: int = 0
        self._start_time: float = time.time()
        self._sniffer_alive: bool = True
        self._sniffer_error: str | None = None

        # ---- pause / scroll state (mutated from the render thread) -------
        # paused: feed is frozen; scroll_offset = how many rows back from the
        # newest packet the viewport's BOTTOM sits. 0 = live (showing newest).
        self._paused: bool = False
        self._scroll_offset: int = 0
        # Snapshot of the packet list taken at pause-time. Stored as a real
        # list copy so deque rotation after pausing can't shift the window.
        self._frozen_packets: list = []

        # ---- focus / alert scroll (render thread only) -------------------
        # focus: which panel arrow keys currently drive ("packets" or "alerts")
        # alert_scroll_offset: alerts scrolled back from newest (0 = newest)
        self._focus: str = "packets"
        self._alert_scroll_offset: int = 0

    # ------------------- pause / scroll control (render thread) ----------

    def toggle_pause(self) -> bool:
        """Flip paused state. On resume, snap back to live. Returns new state."""
        with self._lock:
            self._paused = not self._paused
            if self._paused:
                self._frozen_packets = list(self._packets)
            else:
                self._scroll_offset = 0  # snap-to-live on resume
                self._frozen_packets = []
            return self._paused

    def is_paused(self) -> bool:
        with self._lock:
            return self._paused

    def scroll(self, rows: int, viewport: int) -> None:
        """
        Move the viewport by `rows` (negative = toward older, positive = newer).
        `viewport` is how many rows are visible, used to clamp the offset so we
        never scroll past the ends. Scrolling AUTO-PAUSES the feed — otherwise
        new packets keep shifting the buffer underneath and the window can't
        hold still, making scroll appear to do nothing.
        """
        with self._lock:
            if not self._paused:
                self._paused = True
                self._frozen_packets = list(self._packets)
            self._apply_scroll(rows, viewport)

    def scroll_to_end(self, which: str, viewport: int = 1) -> None:
        """
        Jump to oldest ('home') or newest ('end').

        'home' auto-pauses and jumps to the oldest visible page.
        'end' snaps to live and RESUMES the feed.
        """
        with self._lock:
            if which == "end":
                self._scroll_offset = 0
                self._paused = False
                self._frozen_packets = []
            else:  # home: pause and jump to oldest visible page
                if not self._paused:
                    self._paused = True
                    self._frozen_packets = list(self._packets)
                buf_len = len(self._frozen_packets)
                self._scroll_offset = max(0, buf_len - viewport)

    def get_focus(self) -> str:
        """Return current focus without doing a full snapshot copy."""
        with self._lock:
            return self._focus

    def cycle_focus(self) -> str:
        """Toggle focus between packets and alerts panels. Returns new focus."""
        with self._lock:
            self._focus = "alerts" if self._focus == "packets" else "packets"
            return self._focus

    def scroll_alerts(self, rows: int, viewport: int) -> None:
        """
        Scroll the alerts panel. `rows` in alert units, negative = up (older).
        `viewport` is the number of alerts visible — used to clamp so you can't
        scroll further than there's history to show.
        """
        with self._lock:
            max_offset = max(0, len(self._alerts) - viewport)
            self._alert_scroll_offset = max(
                0, min(max_offset, self._alert_scroll_offset - rows)
            )

    def scroll_alerts_to_end(self, which: str, viewport: int = 1) -> None:
        """Jump alerts viewport to newest ('end') or oldest ('home')."""
        with self._lock:
            if which == "end":
                self._alert_scroll_offset = 0
            else:
                self._alert_scroll_offset = max(0, len(self._alerts) - viewport)

    def _apply_scroll(self, rows: int, viewport: int) -> None:
        """Clamp-and-set scroll offset. Caller holds the lock."""
        buf_len = len(self._frozen_packets) if self._paused else len(self._packets)
        max_offset = max(0, buf_len - viewport)
        self._scroll_offset = max(0, min(max_offset, self._scroll_offset - rows))

    # ------------------- writers (called from sniffer thread) ------------

    def record_packet(self, info: dict) -> None:
        with self._lock:
            self._total_packets += 1
            self._packets.append(info)

            src = info.get("src")
            if src and src != "?":
                length = info.get("length", 0) or 0
                self._talkers[src] += length  # kept for all-time stats if needed
                # Append to the rolling window (bucketed by whole second).
                now = int(time.time())
                self._talker_window.append((now, src, length))

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

    def _top_talkers_windowed(self, n: int = 5) -> list:
        """
        Top `n` source IPs by bytes within the rolling window. Caller holds
        the lock. Evicts buckets older than the window as a side effect, so
        the deque stays bounded on a long-running capture.
        """
        cutoff = int(time.time()) - self._talker_window_seconds
        win = self._talker_window
        while win and win[0][0] <= cutoff:
            win.popleft()
        totals: Counter[str] = Counter()
        for _sec, ip, length in win:
            totals[ip] += length
        return totals.most_common(n)

    # ------------------- reader (called from main/render thread) ---------

    def snapshot(self) -> dict:
        """Return a consistent point-in-time copy of all state for rendering."""
        with self._lock:
            return {
                "uptime":         time.time() - self._start_time,
                "packets":        self._frozen_packets if self._paused else list(self._packets),
                "alerts":         list(self._alerts),
                "total_packets":  self._total_packets,
                "total_alerts":   self._total_alerts,
                "top_talkers":         self._top_talkers_windowed(5),
                "top_talkers_alltime": self._talkers.most_common(5),
                "protocols":      dict(self._protocols),
                "sniffer_alive":  self._sniffer_alive,
                "sniffer_error":  self._sniffer_error,
                "paused":         self._paused,
                "scroll_offset":  self._scroll_offset,
                "buffer_size":    len(self._packets),
                "focus":          self._focus,
                "alert_scroll_offset": self._alert_scroll_offset,
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
        f"{status}  "
        f"Pkts: [bold cyan]{snap['total_packets']:,}[/bold cyan]  "
        f"Alerts: [bold red]{snap['total_alerts']}[/bold red]"
    )
    center = Text.from_markup(
        f"Uptime: [bold]{_format_uptime(snap['uptime'])}[/bold]",
        justify="center",
    )
    right = Text.from_markup(
        "[dim]Tab=focus  Space=pause  q=quit[/dim]",
        justify="right",
    )

    # Three equal-ratio columns so the uptime sits in the true center of the
    # terminal width rather than just center-aligned within a variable column.
    grid = Table.grid(expand=True, padding=(0, 1))
    grid.add_column(justify="left",  ratio=1)
    grid.add_column(justify="center", ratio=1)
    grid.add_column(justify="right",  ratio=1)
    grid.add_row(left, center, right)

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

    all_packets = snap["packets"]
    offset = snap.get("scroll_offset", 0)

    if max_rows is not None and max_rows > 0:
        if offset > 0:
            # Viewport bottom sits `offset` rows back from the newest packet.
            # Slice a window of `max_rows` ending at (len - offset).
            end = max(0, len(all_packets) - offset)
            start = max(0, end - max_rows)
            packets = all_packets[start:end]
        else:
            packets = all_packets[-max_rows:]
    else:
        packets = all_packets

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

    focused_packets = snap.get("focus") != "alerts"
    focus_badge = " [bold reverse cyan] FOCUSED [/bold reverse cyan]" if focused_packets else ""
    scroll_note = f" [dim](−{offset} rows)[/dim]" if offset > 0 else ""
    if snap.get("paused"):
        border = "yellow"
    else:
        border = "cyan"
    title = f"[bold]Live Packets[/bold]{focus_badge}{scroll_note}"

    return Panel(table, title=title, border_style=border, padding=(0, 1))


def render_alerts(snap: dict, max_alerts: int = 20) -> Panel:
    alerts = snap["alerts"]
    focused = snap.get("focus") == "alerts"
    skip = snap.get("alert_scroll_offset", 0)
    border = "red"
    focus_badge = " [bold reverse red] FOCUSED [/bold reverse red]" if focused else ""
    if not alerts:
        return Panel(
            Align.center(Text("no alerts yet", style="dim italic"),
                         vertical="middle"),
            title=f"[bold]Alerts[/bold]{focus_badge}",
            border_style=border,
        )

    total = len(alerts)

    # Sliding window: newest alerts sit at the bottom of the visible window.
    # `skip` = how many alerts we've scrolled up past (hidden from the bottom).
    # end is exclusive; it marks the boundary just past the newest visible alert.
    end   = total - skip           # newest visible = alerts[end-1]
    start = max(0, end - max_alerts)
    visible_alerts = alerts[start:end]

    chunks: list = []
    for i, alert in enumerate(visible_alerts):
        alert_num = start + i + 1   # #1 = oldest in buffer, stable as we scroll

        sev = (alert.get("severity") or "low").lower()
        style = SEVERITY_STYLES.get(sev, "white")
        icon = "⚠" if sev in ("high", "critical") else "◐"
        atype = (alert.get("type") or "?").upper()
        ts = (alert.get("timestamp") or "")[-8:]

        src = alert.get("source", "?")
        src_ip = src.rsplit(":", 1)[0] if ":" in src else src
        src_org = ipnames.resolve(src_ip)
        src_disp = f"{src} [{ORG_STYLE}]({src_org})[/{ORG_STYLE}]" if src_org else src

        dst = alert.get("destination_ip") or "—"
        dst_org = ipnames.resolve(dst) if dst != "—" else None
        dst_disp = f"{dst} [{ORG_STYLE}]({dst_org})[/{ORG_STYLE}]" if dst_org else dst

        msg = alert.get("message", "")

        chunks.append(Text.from_markup(
            f"[dim]#{alert_num:<3}[/dim] [{style}]{icon}  {sev.upper():<8} {atype:<14} {ts}[/{style}]"
        ))
        chunks.append(Text.from_markup(
            f"     [dim]src=[/dim]{src_disp}  [dim]dst=[/dim]{dst_disp}"
        ))
        chunks.append(Text.from_markup(f"     [dim]{msg}[/dim]"))
        chunks.append(Text(""))

    scroll_note = f" [dim](−{skip} rows)[/dim]" if skip > 0 else ""
    return Panel(Group(*chunks),
                 title=f"[bold]Alerts[/bold]{focus_badge}{scroll_note}",
                 border_style=border, padding=(0, 1))


def _render_talker_graph(talkers: list, title: str) -> Group | Text:
    """Render a single top-talkers bar graph block."""
    if not talkers:
        return Text(f"{title}: (none yet)", style="dim italic")
    bar_width = 14
    max_bytes = max(b for _, b in talkers) or 1
    renderables: list = [Text.from_markup(f"[bold]{title}[/bold]")]
    for ip, b in talkers:
        filled = int(round((b / max_bytes) * bar_width))
        bar = "█" * filled + "░" * (bar_width - filled)
        org = ipnames.resolve(ip)
        label = f"{ip} [{ORG_STYLE}]({org})[/{ORG_STYLE}]" if org else ip
        renderables.append(Text.from_markup(
            f"[magenta]{bar}[/magenta] [bold]{_format_bytes(b):>9}[/bold]  {label}"
        ))
    return Group(*renderables)


def render_footer(snap: dict) -> Panel:
    # ---- protocol breakdown with mini bars --------------------------------
    total = sum(snap["protocols"].values())
    if total > 0:
        bar_width = 12
        proto_renderables: list = [Text.from_markup("[bold]Protocols[/bold]")]
        for proto in ("TCP", "UDP", "ICMP", "Other"):
            count = snap["protocols"].get(proto, 0)
            pct = (count / total) * 100 if total else 0
            filled = int(round(pct / 100 * bar_width))
            bar = "█" * filled + "░" * (bar_width - filled)
            style = PROTOCOL_STYLES.get(proto, "white")
            # Non-breaking spaces keep the count attached to the percentage
            # so rich never line-breaks in the middle of the row.
            proto_renderables.append(Text.from_markup(
                f"[{style}]{proto:<5}[/{style}] {bar}\xa0"
                f"[bold]{pct:>5.1f}%[/bold]\xa0[dim]({count:,})[/dim]"
            ))
        proto_block = Group(*proto_renderables)
    else:
        proto_block = Text("no traffic yet", style="dim italic")

    # ---- top talkers: two separate graphs side by side --------------------
    recent_block = _render_talker_graph(snap["top_talkers"], "Top Talkers (60s)")
    alltime_block = _render_talker_graph(snap["top_talkers_alltime"], "Top Talkers (All Time)")

    # Three columns: protocols | recent talkers | all-time talkers
    grid = Table.grid(expand=True, padding=(0, 2))
    grid.add_column(ratio=1)
    grid.add_column(ratio=1)
    grid.add_column(ratio=1)
    grid.add_row(proto_block, recent_block, alltime_block)

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
        Layout(name="footer", size=9),
    )
    layout["main"].split_row(
        Layout(name="packets"),
        Layout(name="alerts"),
    )
    return layout


# Fixed vertical chrome around the packet rows: header(3) + footer(10) +
# packet panel borders/title(2) + table header row(1). Used to work out how
# many packet rows actually fit so a fullscreen window stays full.
_VERTICAL_CHROME = 3 + 9 + 2 + 1


def _packet_capacity(console_height: int) -> int:
    """How many packet rows fit given the current terminal height."""
    return max(5, console_height - _VERTICAL_CHROME)


def _alert_capacity(console_height: int) -> int:
    """
    How many alerts fit in the alerts panel at the current terminal height.
    Each alert is 4 lines (header + src/dst + message + blank).
    Chrome: header(3) + footer(9) + main borders(2) + alert panel borders+title(3).
    """
    lines_available = max(4, console_height - 3 - 9 - 2 - 3)
    return max(1, lines_available // 4 + 1)


def _refresh(layout: Layout, state: TUIState,
             packet_rows: int, alert_rows: int) -> None:
    snap = state.snapshot()
    layout["header"].update(render_header(snap))
    layout["footer"].update(render_footer(snap))
    layout["packets"].update(render_packets(snap, max_rows=packet_rows))
    layout["alerts"].update(render_alerts(snap, max_alerts=alert_rows))


def _handle_key(key: str, state: TUIState,
                viewport: int, alert_viewport: int) -> bool:
    """
    Apply one key press to the state. Returns True if the user asked to quit.
    Tab cycles focus; arrow/page/home/end drive the focused panel.
    `viewport` = visible packet rows, `alert_viewport` = visible alert rows.
    """
    if key in ("q", "Q"):
        return True
    if key == "SPACE":
        state.toggle_pause()
        return False
    if key in ("TAB", "\t"):
        state.cycle_focus()
        return False

    focus = state.get_focus()
    if focus == "alerts":
        if key == "UP":
            state.scroll_alerts(-1, alert_viewport)
        elif key == "DOWN":
            state.scroll_alerts(1, alert_viewport)
        elif key == "PAGEUP":
            state.scroll_alerts(-alert_viewport, alert_viewport)
        elif key == "PAGEDOWN":
            state.scroll_alerts(alert_viewport, alert_viewport)
        elif key == "HOME":
            state.scroll_alerts_to_end("home", alert_viewport)
        elif key == "END":
            state.scroll_alerts_to_end("end")
    else:
        if key == "UP":
            state.scroll(-1, viewport)
        elif key == "DOWN":
            state.scroll(1, viewport)
        elif key == "PAGEUP":
            state.scroll(-viewport, viewport)
        elif key == "PAGEDOWN":
            state.scroll(viewport, viewport)
        elif key == "HOME":
            state.scroll_to_end("home", viewport)
        elif key == "END":
            state.scroll_to_end("end")
    return False


def run_tui(state: TUIState, refresh_per_second: int = 8) -> None:
    """
    Run the live dashboard on the calling thread until the user quits
    (Ctrl+C or 'q'). The sniffer must already be running in another
    (daemon) thread that writes into `state`.

    Keyboard shortcuts:
        Tab          switch focus between Packets and Alerts panels
        Space        pause / resume packet feed (snap to live on resume)
        ↑ / ↓        scroll focused panel one row (auto-pauses packets)
        PgUp / PgDn  scroll focused panel one page
        Home / End   jump to oldest / newest in focused panel
        q / Ctrl+C   quit
    """
    layout = build_layout()

    # screen=True swaps to the alt screen buffer — clean exit returns the
    # terminal to its prior state without scrollback pollution.
    # auto_refresh=False: we drive refreshes ourselves so key handling and
    # rendering stay in lockstep and scrolling feels immediate.
    with KeyReader() as keys:
        with Live(layout, screen=True, auto_refresh=False,
                  redirect_stderr=False) as live:
            rows = _packet_capacity(live.console.size.height)
            alert_rows = _alert_capacity(live.console.size.height)
            _refresh(layout, state, rows, alert_rows)
            live.refresh()

            poll_interval = 1.0 / max(refresh_per_second, 1)
            try:
                while True:
                    rows = _packet_capacity(live.console.size.height)
                    alert_rows = _alert_capacity(live.console.size.height)

                    quit_requested = False
                    while True:
                        key = keys.poll()
                        if key is None:
                            break
                        if _handle_key(key, state,
                                       viewport=rows,
                                       alert_viewport=alert_rows):
                            quit_requested = True
                            break
                    if quit_requested:
                        break

                    _refresh(layout, state, rows, alert_rows)
                    live.refresh()
                    time.sleep(poll_interval)
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