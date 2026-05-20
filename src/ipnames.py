"""
ipnames.py
----------
Best-effort mapping of IP addresses to the organization that owns them.

Two mechanisms, checked in order:

  1. A curated table of well-known CIDR ranges for the big providers
     (Cloudflare, Google, AWS, Microsoft, etc.). Fast, offline, deterministic.
  2. Optional reverse-DNS (PTR) lookups, done lazily on a background thread
     and cached, so they never block the render loop. Disabled by default
     because not every environment has working reverse DNS and it can be slow.

Public API:
    resolve(ip) -> str | None      # org name, or None if unknown
    label(ip)   -> str             # "ip" or "ip (Org)" convenience formatter

The CIDR table is intentionally small and covers the providers you're most
likely to see in normal traffic. It is NOT authoritative — provider IP space
changes constantly — but it's accurate enough to make a dashboard readable.
"""

import ipaddress
import socket
import threading
from functools import lru_cache


# ---------------------------------------------------------------------------
# Curated CIDR → organization table.
# Ranges are approximate / representative, not exhaustive. Sourced from each
# provider's published ranges; trimmed to the most common blocks.
# ---------------------------------------------------------------------------
_ORG_RANGES: list[tuple[str, str]] = [
    # Cloudflare
    ("104.16.0.0/13", "Cloudflare"),
    ("104.24.0.0/14", "Cloudflare"),
    ("104.28.0.0/14", "Cloudflare"),
    ("162.158.0.0/15", "Cloudflare"),
    ("172.64.0.0/13", "Cloudflare"),
    ("173.245.48.0/20", "Cloudflare"),
    ("103.21.244.0/22", "Cloudflare"),
    ("141.101.64.0/18", "Cloudflare"),
    ("190.93.240.0/20", "Cloudflare"),
    ("188.114.96.0/20", "Cloudflare"),
    ("197.234.240.0/22", "Cloudflare"),
    ("198.41.128.0/17", "Cloudflare"),
    # Google (incl. Google DNS 8.8.8.8 / 8.8.4.4)
    ("8.8.4.0/24", "Google"),
    ("8.8.8.0/24", "Google"),
    ("8.34.208.0/20", "Google"),
    ("8.35.192.0/20", "Google"),
    ("34.0.0.0/9", "Google Cloud"),
    ("35.190.0.0/17", "Google Cloud"),
    ("35.191.0.0/16", "Google Cloud"),
    ("142.250.0.0/15", "Google"),
    ("172.217.0.0/16", "Google"),
    ("172.253.0.0/16", "Google"),
    ("216.58.192.0/19", "Google"),
    ("64.233.160.0/19", "Google"),
    ("74.125.0.0/16", "Google"),
    ("209.85.128.0/17", "Google"),
    # Amazon AWS
    ("3.0.0.0/9", "Amazon AWS"),
    ("13.32.0.0/15", "Amazon AWS"),
    ("13.224.0.0/14", "Amazon AWS"),
    ("15.177.0.0/18", "Amazon AWS"),
    ("16.0.0.0/9", "Amazon AWS"),
    ("18.32.0.0/11", "Amazon AWS"),
    ("34.192.0.0/10", "Amazon AWS"),
    ("35.152.0.0/13", "Amazon AWS"),
    ("52.0.0.0/11", "Amazon AWS"),
    ("54.64.0.0/11", "Amazon AWS"),
    ("99.80.0.0/15", "Amazon AWS"),
    ("204.236.128.0/17", "Amazon AWS"),
    # Microsoft / Azure
    ("13.64.0.0/11", "Microsoft Azure"),
    ("20.0.0.0/8", "Microsoft Azure"),
    ("40.64.0.0/10", "Microsoft Azure"),
    ("52.224.0.0/11", "Microsoft Azure"),
    ("104.40.0.0/13", "Microsoft Azure"),
    ("131.253.0.0/16", "Microsoft"),
    ("157.54.0.0/15", "Microsoft"),
    ("204.79.195.0/24", "Microsoft"),
    # Meta / Facebook
    ("31.13.24.0/21", "Meta"),
    ("31.13.64.0/18", "Meta"),
    ("66.220.144.0/20", "Meta"),
    ("69.63.176.0/20", "Meta"),
    ("157.240.0.0/16", "Meta"),
    ("173.252.64.0/18", "Meta"),
    # Apple
    ("17.0.0.0/8", "Apple"),
    # Akamai
    ("23.32.0.0/11", "Akamai"),
    ("23.192.0.0/11", "Akamai"),
    ("104.64.0.0/10", "Akamai"),
    ("184.24.0.0/13", "Akamai"),
    # Fastly
    ("151.101.0.0/16", "Fastly"),
    # Netflix
    ("45.57.0.0/17", "Netflix"),
    ("208.75.76.0/22", "Netflix"),
    # Valve / Steam
    ("155.133.224.0/19", "Valve/Steam"),
    ("162.254.192.0/21", "Valve/Steam"),
    ("205.196.6.0/24", "Valve/Steam"),
    # GitHub
    ("140.82.112.0/20", "GitHub"),
    ("185.199.108.0/22", "GitHub"),
    ("192.30.252.0/22", "GitHub"),
    # Private / local ranges — labeled so they're obviously internal
    ("10.0.0.0/8", "Private LAN"),
    ("172.16.0.0/12", "Private LAN"),
    ("192.168.0.0/16", "Private LAN"),
    ("169.254.0.0/16", "Link-local"),
    ("127.0.0.0/8", "Loopback"),
    ("224.0.0.0/4", "Multicast"),
    ("255.255.255.255/32", "Broadcast"),
]

# Pre-parse the table once into (network, org) tuples for fast matching.
_PARSED_RANGES: list[tuple[ipaddress._BaseNetwork, str]] = [
    (ipaddress.ip_network(cidr), org) for cidr, org in _ORG_RANGES
]


# ---- optional reverse-DNS cache (off by default) --------------------------
_rdns_enabled = False
_rdns_cache: dict[str, str | None] = {}
_rdns_lock = threading.Lock()
_rdns_inflight: set[str] = set()


def enable_reverse_dns(enabled: bool = True) -> None:
    """Turn lazy background reverse-DNS lookups on or off."""
    global _rdns_enabled
    _rdns_enabled = enabled


def _rdns_worker(ip: str) -> None:
    """Background PTR lookup; stores result (or None) in the cache."""
    name = None
    try:
        socket.setdefaulttimeout(1.0)
        host, _, _ = socket.gethostbyaddr(ip)
        name = host
    except (socket.herror, socket.gaierror, OSError):
        name = None
    with _rdns_lock:
        _rdns_cache[ip] = name
        _rdns_inflight.discard(ip)


def _maybe_start_rdns(ip: str) -> str | None:
    """Return a cached PTR name if present; otherwise kick off a lookup."""
    with _rdns_lock:
        if ip in _rdns_cache:
            return _rdns_cache[ip]
        if ip not in _rdns_inflight:
            _rdns_inflight.add(ip)
            threading.Thread(target=_rdns_worker, args=(ip,), daemon=True).start()
    return None  # not ready yet; a future render tick will pick it up


@lru_cache(maxsize=4096)
def _match_cidr(ip: str) -> str | None:
    """Match an IP against the curated CIDR table. Cached per IP."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for network, org in _PARSED_RANGES:
        # Skip mismatched IP versions cheaply.
        if addr.version != network.version:
            continue
        if addr in network:
            return org
    return None


def resolve(ip: str | None) -> str | None:
    """
    Return the organization name for `ip`, or None if unknown.

    Always tries the fast CIDR table first. If reverse DNS is enabled and the
    CIDR table misses, returns a cached PTR hostname when available (and
    schedules a background lookup otherwise).
    """
    if not ip or ip == "?":
        return None

    org = _match_cidr(ip)
    if org is not None:
        return org

    if _rdns_enabled:
        return _maybe_start_rdns(ip)

    return None


def label(ip: str | None) -> str:
    """Format an IP as 'ip' or 'ip (Org)' when the org is known."""
    if not ip:
        return "?"
    org = resolve(ip)
    return f"{ip} ({org})" if org else ip


# ---- self-test ------------------------------------------------------------
if __name__ == "__main__":
    samples = [
        "104.29.157.64",    # Cloudflare
        "162.159.130.234",  # Cloudflare
        "8.8.8.8",          # Google
        "142.250.80.110",   # Google
        "140.82.116.4",     # GitHub
        "16.15.254.189",    # Amazon AWS
        "17.253.144.10",    # Apple
        "10.16.98.107",     # Private LAN
        "192.168.1.1",      # Private LAN
        "203.0.113.99",     # unknown (TEST-NET-3)
    ]
    print("IP → organization lookup test:")
    for ip in samples:
        print(f"  {ip:<18} → {resolve(ip) or '(unknown)'}")