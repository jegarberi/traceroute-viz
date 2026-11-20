"""OpenStreetMap tiles with a local disk cache (stdlib only).

A tile is downloaded at most once: it is stored at <cache>/<z>/<x>/<y>.png and any later request
reads that file. Failed downloads are not cached, so they are retried on the next run.

Usage policy (https://operations.osmfoundation.org/policies/tiles/): the request identifies this
app in its User-Agent, requests are throttled, and the map shows the attribution below.
"""
import base64
import math
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

URL = "https://tile.openstreetmap.org/{z}/{x}/{y}.png"
USER_AGENT = "traceviz-local/0.1 (local traceroute visualiser)"
ATTRIBUTION = "© OpenStreetMap contributors"
TILE = 256
MIN_INTERVAL = 0.5  # seconds between network requests
HERE = Path(__file__).resolve().parent
DEFAULT_CACHE = HERE / "tile_cache"

_last_request = [0.0]


def merc_xy(lat, lon, z):
    """Web Mercator world-pixel coordinates at zoom z (the world is TILE * 2**z pixels wide)."""
    n = TILE * 2 ** z
    lat = max(min(lat, 85.0511), -85.0511)
    x = (lon + 180) / 360 * n
    s = math.sin(math.radians(lat))
    y = (0.5 - math.log((1 + s) / (1 - s)) / (4 * math.pi)) * n
    return x, y


def tile_path(cache, z, x, y):
    return Path(cache) / str(z) / str(x) / f"{y}.png"


def get_tile(z, x, y, cache=DEFAULT_CACHE, fetch=True):
    """Path of the cached tile, downloading it first if it is missing. None if unavailable."""
    p = tile_path(cache, z, x, y)
    if p.exists() and p.stat().st_size > 0:
        return p
    if not fetch:
        return None
    wait = MIN_INTERVAL - (time.monotonic() - _last_request[0])
    if wait > 0:
        time.sleep(wait)
    _last_request[0] = time.monotonic()
    req = urllib.request.Request(URL.format(z=z, x=x, y=y), headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = resp.read()
    except (urllib.error.URLError, OSError) as e:
        print(f"note: tile {z}/{x}/{y} unavailable: {e}", file=sys.stderr)
        return None
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".part")
    tmp.write_bytes(data)
    os.replace(tmp, p)
    return p


def fetch_world(z, cache=DEFAULT_CACHE, fetch=True):
    """{(x, y): path} for every tile of the world at zoom z. Missing tiles are left out."""
    n = 2 ** z
    out = {}
    for x in range(n):
        for y in range(n):
            p = get_tile(z, x, y, cache, fetch)
            if p is not None:
                out[(x, y)] = p
    return out


def data_uri(path):
    return "data:image/png;base64," + base64.b64encode(Path(path).read_bytes()).decode()
