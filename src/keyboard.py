"""
keyboard.py
-----------
Cross-platform non-blocking keyboard input for the TUI.

The TUI's render loop polls `KeyReader.poll()` once per tick; it returns a
normalized key name (or None if no key is waiting) without ever blocking the
loop. Arrow keys, Page Up/Down, Home/End, and printable characters are all
normalized to stable string names so the caller doesn't deal with raw escape
sequences or platform quirks.

Normalized key names returned by poll():
    "UP" "DOWN" "LEFT" "RIGHT"
    "PAGEUP" "PAGEDOWN" "HOME" "END"
    "ENTER" "ESC" "SPACE"
    single characters for printable keys, e.g. "q", "p", "/"

Usage:
    with KeyReader() as keys:
        while running:
            key = keys.poll()
            if key == "q":
                break
            ...
            time.sleep(0.25)

The context manager form is important on Unix: it puts the terminal into
cbreak mode on entry and ALWAYS restores the previous mode on exit, even if
the body raises. On Windows it's a no-op wrapper around msvcrt.
"""

import sys


# Detect platform once. msvcrt only exists on Windows.
try:
    import msvcrt  # type: ignore
    _PLATFORM = "windows"
except ImportError:
    msvcrt = None  # type: ignore
    _PLATFORM = "unix"
    import select
    import termios
    import tty


class KeyReader:
    """Non-blocking key reader. Use as a context manager."""

    def __init__(self):
        self._fd = None
        self._old_settings = None
        self._enabled = sys.stdin is not None and sys.stdin.isatty()

    # ------------------------------------------------------------------
    # Context manager: set up / tear down terminal mode (Unix only).
    # ------------------------------------------------------------------

    def __enter__(self):
        if self._enabled and _PLATFORM == "unix":
            self._fd = sys.stdin.fileno()
            self._old_settings = termios.tcgetattr(self._fd)
            tty.setcbreak(self._fd)  # char-at-a-time, no echo, signals intact
        return self

    def __exit__(self, *exc):
        if self._old_settings is not None:
            termios.tcsetattr(self._fd, termios.TCSADRAIN, self._old_settings)
            self._old_settings = None
        return False  # don't suppress exceptions

    # ------------------------------------------------------------------
    # Polling
    # ------------------------------------------------------------------

    def poll(self) -> str | None:
        """Return one normalized key name, or None if nothing is waiting."""
        if not self._enabled:
            return None
        if _PLATFORM == "windows":
            return self._poll_windows()
        return self._poll_unix()

    # ---- Windows -----------------------------------------------------

    def _poll_windows(self) -> str | None:
        if not msvcrt.kbhit():
            return None
        ch = msvcrt.getwch()
        # Arrow / nav keys arrive as a two-char sequence beginning with
        # '\x00' or '\xe0'; the second char identifies the key.
        if ch in ("\x00", "\xe0"):
            if not msvcrt.kbhit():
                return None
            code = msvcrt.getwch()
            return {
                "H": "UP", "P": "DOWN", "K": "LEFT", "M": "RIGHT",
                "I": "PAGEUP", "Q": "PAGEDOWN", "G": "HOME", "O": "END",
                ";": "F1",  # F1 arrives as prefix + ';'
            }.get(code)
        return self._normalize_simple(ch)

    # ---- Unix --------------------------------------------------------

    def _poll_unix(self) -> str | None:
        # select with zero timeout = non-blocking check for input.
        if not select.select([sys.stdin], [], [], 0)[0]:
            return None
        ch = sys.stdin.read(1)
        if ch == "\x1b":
            # Possible escape sequence (arrows, page, home/end, F-keys). Read
            # the rest if it's immediately available; else it's a bare ESC.
            if not select.select([sys.stdin], [], [], 0)[0]:
                return "ESC"
            seq = sys.stdin.read(1)
            # SS3 sequences: ESC O <x>. F1 is commonly ESC O P.
            if seq == "O":
                if not select.select([sys.stdin], [], [], 0)[0]:
                    return "ESC"
                code = sys.stdin.read(1)
                return {"P": "F1", "Q": "F2", "R": "F3", "S": "F4",
                        "H": "HOME", "F": "END"}.get(code)
            if seq != "[":
                return "ESC"
            seq = sys.stdin.read(1)
            # Simple arrows: ESC [ A/B/C/D
            simple = {"A": "UP", "B": "DOWN", "C": "RIGHT", "D": "LEFT",
                      "H": "HOME", "F": "END"}
            if seq in simple:
                return simple[seq]
            # Extended: ESC [ <n> ~  (PageUp=5, PageDown=6, Home=1/7, End=4/8,
            # and F1 as ESC [ 1 1 ~ on some terminals).
            if seq.isdigit():
                num = seq
                # read until '~'
                while select.select([sys.stdin], [], [], 0)[0]:
                    c = sys.stdin.read(1)
                    if c == "~":
                        break
                    num += c
                return {
                    "5": "PAGEUP", "6": "PAGEDOWN",
                    "1": "HOME", "7": "HOME", "4": "END", "8": "END",
                    "11": "F1", "12": "F2", "13": "F3", "14": "F4",
                }.get(num)
            return None
        return self._normalize_simple(ch)

    # ---- shared ------------------------------------------------------

    @staticmethod
    def _normalize_simple(ch: str) -> str | None:
        if ch in ("\r", "\n"):
            return "ENTER"
        if ch == " ":
            return "SPACE"
        if ch == "\x03":  # Ctrl+C — let the caller decide (usually re-raise)
            raise KeyboardInterrupt
        if ch.isprintable():
            return ch
        return None


# ----------------------------------------------------------------------
# Self-test: echo normalized key names until 'q'. Run:  python keyboard.py
# ----------------------------------------------------------------------

if __name__ == "__main__":
    import time

    print("Press keys (arrows, PgUp/PgDn, Home/End, Space, Enter). 'q' quits.")
    with KeyReader() as keys:
        while True:
            k = keys.poll()
            if k is not None:
                print(f"  key: {k!r}")
                if k == "q":
                    break
            time.sleep(0.03)
    print("done.")