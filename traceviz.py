#!/usr/bin/env python3
"""traceviz: render traceroute.db as one self-contained HTML report.

Stdlib only, read-only on the database.

  python3 traceviz.py                        # ../traceroute/traceroute.db -> ./report.html
  python3 traceviz.py --db X.db --out r.html
  python3 traceviz.py --geo-dir DIR          # GeoLite2-City/ASN .mmdb location (default: ../traceroute)

Schema (from src/database.c): ips(id, ip uint32 big-endian), paths(path_id, path = "id,id,...")
where ip id 0-valued IP means "*" (no reply), tracerts(ip_destination_id, path_id, ts epoch).

GeoIP/ASN lookups need the optional `maxminddb` package. Run with .venv/bin/python3
(created with: python3 -m venv .venv && .venv/bin/pip install maxminddb). Without it,
or without the .mmdb files, the GeoIP sections are left out.
"""
import argparse
import collections
import datetime as dt
import hashlib
import html
import ipaddress
import sqlite3
import sys
from pathlib import Path

from tiles import ATTRIBUTION, TILE, data_uri, fetch_world, merc_xy

try:
    import maxminddb
except ImportError:
    maxminddb = None

HERE = Path(__file__).resolve().parent
NO_REPLY_IP = 0  # ips.ip == 0 is the "*" hop, see ip_uint32_to_sz() in src/utils.c
PALETTE = ["#4e79a7", "#f28e2b", "#e15759", "#76b7b2", "#59a14f",
           "#edc948", "#b07aa1", "#ff9da7", "#9c755f", "#bab0ac"]
NO_HOP_COLOR = "#8a8a85"
CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")

STYLE = """
:root{--bg:#fafaf7;--fg:#1d1d1b;--muted:#6b6b66;--card:#ffffff;--line:#e4e2dc;--accent:#4e79a7}
@media (prefers-color-scheme: dark){:root:not([data-theme="light"]){--bg:#15161a;--fg:#e8e6e1;--muted:#9a9891;--card:#1d1f25;--line:#2e3038;--accent:#7fa7d6}}
:root[data-theme="dark"]{--bg:#15161a;--fg:#e8e6e1;--muted:#9a9891;--card:#1d1f25;--line:#2e3038;--accent:#7fa7d6}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,sans-serif}
main{padding:16px;max-width:1100px;margin:0 auto}
h1{font-size:22px;margin:8px 0 2px}
h2{font-size:16px;margin:0 0 8px}
section{margin-top:26px}
.muted{color:var(--muted)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin-top:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 12px}
.card b{display:block;font-size:22px}
.wrap{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px}
svg{width:100%;height:auto;display:block;min-width:600px}
svg text{fill:var(--fg);font-size:11px}
svg .grid{stroke:var(--line)}
svg .bar{fill:var(--accent)}
svg .cell{fill:var(--accent)}
svg .muted-txt{fill:var(--muted);font-size:10px}
svg .attrib{fill:#222;font-size:10px;paint-order:stroke;stroke:#fff;stroke-width:3px}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{text-align:left;padding:5px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{white-space:nowrap;color:var(--muted);font-weight:600}
.route{font-family:ui-monospace,monospace;font-size:12px;word-break:break-word}
.legend{display:flex;flex-wrap:wrap;gap:4px 14px;margin-bottom:8px;font-size:12px}
.swatch{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:6px;vertical-align:middle}
"""


def esc(s):
    return html.escape(str(s))


def fmt_ip(ip):
    if ip == NO_REPLY_IP:
        return "*"
    return ".".join(str((ip >> shift) & 0xFF) for shift in (24, 16, 8, 0))


def fmt_ts(ts):
    return dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def tlabel(ts):
    return dt.datetime.fromtimestamp(ts).strftime("%H:%M")


def load(db_path):
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        ips = dict(con.execute("SELECT id, ip FROM ips"))
        paths = {pid: tuple(int(h) for h in (p or "").split(",") if h)
                 for pid, p in con.execute("SELECT path_id, path FROM paths")}
        traces = con.execute("SELECT ts, ip_destination_id, path_id FROM tracerts ORDER BY ts, id").fetchall()
    finally:
        con.close()
    return ips, paths, traces


def geo_lookup(ips, geo_dir):
    """ip id -> {private, country, city, lat, lon, asn, org}, or None if no databases can be read."""
    if maxminddb is None:
        print("note: maxminddb not installed, skipping GeoIP/ASN", file=sys.stderr)
        return None
    city_path = Path(geo_dir) / "GeoLite2-City.mmdb"
    asn_path = Path(geo_dir) / "GeoLite2-ASN.mmdb"
    city = maxminddb.open_database(str(city_path)) if city_path.exists() else None
    asn = maxminddb.open_database(str(asn_path)) if asn_path.exists() else None
    if city is None and asn is None:
        print(f"note: no GeoLite2 .mmdb files in {geo_dir}, skipping GeoIP/ASN", file=sys.stderr)
        return None
    out = {}
    for h, ip in ips.items():
        if ip == NO_REPLY_IP:
            continue
        addr = fmt_ip(ip)
        parsed = ipaddress.ip_address(addr)
        # 100.64.0.0/10 is carrier-grade NAT space, which GeoLite does not cover
        cgnat = parsed in CGNAT_NET
        rec = {"private": parsed.is_private or cgnat, "cgnat": cgnat,
               "country": None, "city": None, "lat": None, "lon": None, "asn": None, "org": None}
        if not rec["private"]:
            if city is not None:
                c = city.get(addr) or {}
                rec["country"] = (c.get("country") or {}).get("iso_code")
                rec["city"] = ((c.get("city") or {}).get("names") or {}).get("en")
                loc = c.get("location") or {}
                rec["lat"], rec["lon"] = loc.get("latitude"), loc.get("longitude")
            if asn is not None:
                a = asn.get(addr) or {}
                rec["asn"] = a.get("autonomous_system_number")
                rec["org"] = a.get("autonomous_system_organization")
        out[h] = rec
    for db in (city, asn):
        if db is not None:
            db.close()
    return out


def geo_place(A, h):
    g = A["geo"].get(h)
    if g is None:
        return ""
    if g["private"]:
        return "CGNAT (shared)" if g.get("cgnat") else "private"
    return ", ".join(str(x) for x in (g["city"], g["country"]) if x) or "unknown"


def analyze(ips, paths, traces, geo=None):
    def star(hop):
        return ips[hop] == NO_REPLY_IP

    def real(route):
        return tuple(h for h in route if not star(h))

    by_dest = collections.defaultdict(list)  # dest id -> [(ts, raw route, real route)]
    for ts, dest, pid in traces:
        route = paths.get(pid, ())
        by_dest[dest].append((ts, route, real(route)))

    dests, variants, events = [], {}, []
    for dest, items in sorted(by_dest.items()):
        var = {}  # real route -> [count, first_ts, last_ts]
        prev = None
        changes = reached = no_reply = hops = stars = 0
        for ts, route, r in items:
            if r in var:
                var[r][0] += 1
                var[r][2] = ts
            else:
                var[r] = [1, ts, ts]
            if prev is not None and r != prev:
                changes += 1
                events.append((ts, dest, prev, r))
            prev = r
            if route and route[-1] == dest:
                reached += 1
            if not r:
                no_reply += 1
            hops += len(route)
            stars += sum(star(h) for h in route)
        n = len(items)
        dests.append({
            "dest": dest, "label": fmt_ip(ips[dest]), "n": n,
            "first": items[0][0], "last": items[-1][0],
            "routes": len(var), "changes": changes,
            "reached": reached / n, "no_reply": no_reply, "avg_hops": hops / n,
            "star_pct": stars / hops if hops else 0.0,
        })
        variants[dest] = var

    ip_hits, edges = collections.Counter(), collections.Counter()
    pos_sum, pos_n, hop_grid = collections.Counter(), collections.Counter(), collections.Counter()
    for items in by_dest.values():
        for _, route, _ in items:
            seen = set()
            for i, h in enumerate(route, 1):
                if not star(h):
                    seen.add(h)
                    pos_sum[h] += i
                    pos_n[h] += 1
                    hop_grid[(h, i)] += 1
            ip_hits.update(seen)
            for a, b in zip(route, route[1:]):
                if a != b and not star(a) and not star(b):
                    edges[(a, b)] += 1

    A = {
        "ips": ips, "dests": dests, "variants": variants, "events": events, "by_dest": by_dest,
        "ip_hits": ip_hits, "edges": edges, "hop_grid": hop_grid,
        "column": {h: round(pos_sum[h] / pos_n[h]) for h in pos_n},
        "labels": {d["dest"]: d["label"] for d in dests},
        "geo": geo or {},
        "t0": traces[0][0], "t1": traces[-1][0], "n_traces": len(traces),
        "ip_count": sum(1 for ip in ips.values() if ip != NO_REPLY_IP),
        "routes_total": len({r for v in variants.values() for r in v}),
    }
    A["graph"] = build_graph(A)
    return A


def route_str(ips, route):
    return " → ".join(fmt_ip(ips[h]) for h in route) or "(no replies)"


def route_hue(route):
    return int(hashlib.md5(repr(route).encode()).hexdigest()[:6], 16) % 360


def route_color(route):
    if not route:
        return NO_HOP_COLOR
    return f"hsl({route_hue(route)} 65% 50%)"


def build(db_path, geo_dir, dests=None, t0=None, t1=None):
    """Load + analyze. Optional filters: dests = set of destination ids, t0/t1 = epoch bounds (inclusive)."""
    ips, paths, traces = load(db_path)
    if dests is not None:
        traces = [t for t in traces if t[1] in dests]
    if t0 is not None:
        traces = [t for t in traces if t[0] >= t0]
    if t1 is not None:
        traces = [t for t in traces if t[0] <= t1]
    if not traces:
        raise ValueError(f"no traces in {db_path} match the filter")
    return analyze(ips, paths, traces, geo_lookup(ips, geo_dir))


# Unknown-hop display modes: (key, label, minimum run length to hide; None = keep all)
UNKNOWN_MODES = [("show", "show all *", None), ("hide-multi", "hide runs of 2+ *", 2), ("hide-all", "hide all *", 1)]
MODE_MIN = {key: mn for key, _, mn in UNKNOWN_MODES}


def route_sequence(route, is_star, min_hide=None):
    """Collapse a raw route into graph node keys (ip ids, or ("*", before, after) for unknown hops).

    A run of * between two known hops:
      - same IP on both sides  -> the * are that IP, absorbed (no extra node)
      - different IPs          -> one separate unknown node for the run
      - at the start or end    -> one unknown node next to the single known neighbour
    min_hide: runs of at least this many * are left out entirely (their neighbours are linked directly).
    """
    seq, prev, i, n = [], None, 0, len(route)
    while i < n:
        if not is_star(route[i]):
            if not seq or seq[-1] != route[i]:
                seq.append(route[i])
            prev = route[i]
            i += 1
            continue
        j = i
        while j < n and is_star(route[j]):
            j += 1
        nxt = route[j] if j < n else None
        same_ip = prev is not None and prev == nxt
        hidden = min_hide is not None and (j - i) >= min_hide
        if not same_ip and not hidden and (prev is not None or nxt is not None):
            seq.append(("*", prev, nxt))
        i = j
    return seq


def node_info(A, k):
    if isinstance(k, tuple):
        _, before, after = k
        if before is None:
            label = f"* (before {fmt_ip(A['ips'][after])})"
        elif after is None:
            label = f"* (after {fmt_ip(A['ips'][before])})"
        else:
            label = f"* (between {fmt_ip(A['ips'][before])} and {fmt_ip(A['ips'][after])})"
        return {"key": k, "short": "*", "label": label,
                "kind": "unknown", "place": "", "asn": None, "org": None, "country": None}
    g = A["geo"].get(k) or {}
    return {"key": k, "short": fmt_ip(A["ips"][k]), "label": fmt_ip(A["ips"][k]),
            "kind": "dest" if k in A["labels"] else "ip", "place": geo_place(A, k),
            "asn": g.get("asn"), "org": g.get("org"), "country": g.get("country")}


def build_graph(A, min_hide=None):
    """Hop graph: nodes are IPs (plus unknown nodes), edges are consecutive hops with trace counts."""
    is_star = lambda h: A["ips"][h] == NO_REPLY_IP
    nodes, edges = {}, collections.Counter()
    pos_sum, pos_n, hits = collections.Counter(), collections.Counter(), collections.Counter()
    for items in A["by_dest"].values():
        for _, route, _ in items:
            seq = route_sequence(route, is_star, min_hide)
            for i, k in enumerate(seq, 1):
                if k not in nodes:
                    nodes[k] = node_info(A, k)
                pos_sum[k] += i
                pos_n[k] += 1
            hits.update(set(seq))
            for a, b in zip(seq, seq[1:]):
                if a != b:
                    edges[(a, b)] += 1
    for k, info in nodes.items():
        info["col"] = round(pos_sum[k] / pos_n[k])  # average position along the paths
        info["hits"] = hits[k]
    return {"nodes": nodes, "edges": edges}


def graph_for(A, mode="show"):
    """The hop graph for an unknown-hop display mode (built on demand, cached on A)."""
    if mode == "show":
        return A["graph"]
    cache = A.setdefault("graphs", {})
    if mode not in cache:
        cache[mode] = build_graph(A, MODE_MIN[mode])
    return cache[mode]


def graph_layers(G):
    """Nodes grouped into left-to-right layers by average position; busiest node first in each layer."""
    cols = sorted({n["col"] for n in G["nodes"].values()})
    return [sorted((k for k, n in G["nodes"].items() if n["col"] == c), key=lambda k: -G["nodes"][k]["hits"])
            for c in cols]


def graph_table(A, mode="show"):
    G = graph_for(A, mode)
    headers = ["Layer", "Node", "Traces", "ASN", "Organisation", "Location", "Next hops (traces)"]
    rows = []
    for x, layer in enumerate(graph_layers(G), 1):
        for k in layer:
            n = G["nodes"][k]
            nxt = sorted(((b, c) for (a, b), c in G["edges"].items() if a == k), key=lambda t: -t[1])
            nxt_txt = ", ".join(f'{G["nodes"][b]["short"]} ({c})' for b, c in nxt) or "–"
            rows.append([str(x), n["label"], str(n["hits"]), str(n["asn"] or "–"), n["org"] or "–",
                         n["place"] or "–", nxt_txt])
    return headers, rows


def chart_graph(A, mode="show"):
    G = graph_for(A, mode)
    if not G["nodes"]:
        return '<p class="muted">No hops.</p>'
    layers = graph_layers(G)
    CW, RH, M = 170, 62, 40
    maxrows = max(len(layer) for layer in layers)
    W = 2 * M + len(layers) * CW
    H = 2 * M + maxrows * RH
    pos = {}
    for x, layer in enumerate(layers):
        top = M + (maxrows - len(layer)) * RH / 2
        for y, k in enumerate(layer):
            pos[k] = (M + x * CW + CW / 2, top + y * RH + RH / 2)
    peak = max(G["edges"].values(), default=1)
    out = []
    for (a, b), c in G["edges"].items():
        (xa, ya), (xb, yb) = pos[a], pos[b]
        out.append(f'<line x1="{xa:.1f}" y1="{ya:.1f}" x2="{xb:.1f}" y2="{yb:.1f}" stroke="var(--muted)" '
                   f'stroke-opacity=".6" stroke-width="{1 + 3 * c / peak:.2f}">'
                   f'<title>{esc(G["nodes"][a]["label"])} → {esc(G["nodes"][b]["label"])}: {c} trace(s)</title></line>')
    for k, (x, y) in pos.items():
        n = G["nodes"][k]
        fill = {"dest": "#e15759", "unknown": "none"}.get(n["kind"], "var(--accent)")
        dash = ' stroke-dasharray="3 2" stroke="var(--muted)" stroke-width="1.5"' if n["kind"] == "unknown" else ""
        out.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="9" fill="{fill}"{dash}>'
                   f'<title>{esc(n["label"])} · {esc(n["place"] or "no location")} · '
                   f'{esc(n["org"] or "")} · {n["hits"]} trace(s)</title></circle>')
        out.append(f'<text x="{x:.1f}" y="{y + 24:.1f}" text-anchor="middle">{esc(n["short"])}</text>')
        sub = " ".join(str(v) for v in (f'AS{n["asn"]}' if n["asn"] else "", n["country"] or "") if v)
        if sub:
            out.append(f'<text x="{x:.1f}" y="{y + 37:.1f}" text-anchor="middle" class="muted-txt">{esc(sub)}</text>')
    return svg(W, H, "".join(out))


def dest_table(A):
    headers = ["Destination", "Location", "Traces", "Reached", "Routes", "Changes", "No reply",
               "Avg hops", "* hops", "First", "Last"]
    rows = [[d["label"], geo_place(A, d["dest"]), str(d["n"]), f'{d["reached"]:.0%}', str(d["routes"]),
             str(d["changes"]), str(d["no_reply"]), f'{d["avg_hops"]:.1f}', f'{d["star_pct"]:.0%}',
             fmt_ts(d["first"]), fmt_ts(d["last"])] for d in A["dests"]]
    return headers, rows


def route_table(A):
    rows = []
    for d in A["dests"]:
        for r, (cnt, first, last) in sorted(A["variants"][d["dest"]].items(), key=lambda kv: -kv[1][0]):
            rows.append([d["label"], str(cnt), fmt_ts(first), fmt_ts(last), route_str(A["ips"], r)])
    return ["Destination", "Traces", "First", "Last", "Route"], rows


def change_table(A):
    rows = [[fmt_ts(ts), A["labels"][dest], str(len(prev)), str(len(r)),
             route_str(A["ips"], prev), route_str(A["ips"], r)] for ts, dest, prev, r in A["events"]]
    return ["Time", "Destination", "Hops before", "Hops after", "From", "To"], rows


def ip_table(A):
    rows = []
    for h, hits in A["ip_hits"].most_common():
        g = A["geo"].get(h) or {}
        rows.append([fmt_ip(A["ips"][h]), str(hits), geo_place(A, h) or "–", str(g.get("asn") or "–"),
                     g.get("org") or "–",
                     f'{g["lat"]:.2f}' if g.get("lat") is not None else "–",
                     f'{g["lon"]:.2f}' if g.get("lon") is not None else "–"])
    return ["IP", "Traces", "Location", "ASN", "Organisation", "Lat", "Lon"], rows


def svg(w, h, body):
    return f'<svg viewBox="0 0 {w} {h}" xmlns="http://www.w3.org/2000/svg">{body}</svg>'


def time_axis(A, L, R, y, W):
    return (f'<text x="{L}" y="{y}">{tlabel(A["t0"])}</text>'
            f'<text x="{W - R}" y="{y}" text-anchor="end">{tlabel(A["t1"])}</text>')


def chart_timeline(A):
    W, L, R, T, ROW = 960, 110, 12, 8, 26
    span = max(A["t1"] - A["t0"], 1)
    H = T + ROW * len(A["dests"]) + 24

    def x(ts):
        return L + (ts - A["t0"]) / span * (W - L - R)

    out = []
    for i, d in enumerate(A["dests"]):
        y = T + i * ROW + ROW / 2
        out.append(f'<line class="grid" x1="{L}" x2="{W - R}" y1="{y}" y2="{y}"/>')
        out.append(f'<text x="{L - 8}" y="{y + 4}" text-anchor="end">{esc(d["label"])}</text>')
        for ts, _, r in A["by_dest"][d["dest"]]:
            tip = f'{fmt_ts(ts)} → {d["label"]}: {route_str(A["ips"], r)}'
            out.append(f'<circle cx="{x(ts):.1f}" cy="{y}" r="3" fill="{route_color(r)}" '
                       f'data-dest="{d["dest"]}" data-ts="{ts}">'
                       f'<title>{esc(tip)}</title></circle>')
    out.append(time_axis(A, L, R, H - 6, W))
    return svg(W, H, "".join(out))


def chart_hops(A):
    W, L, R, T, B, H = 960, 36, 12, 8, 22, 220
    span = max(A["t1"] - A["t0"], 1)
    maxh = max((len(route) for items in A["by_dest"].values() for _, route, _ in items), default=1) or 1

    def x(ts):
        return L + (ts - A["t0"]) / span * (W - L - R)

    def y(hops):
        return H - B - hops / maxh * (H - T - B)

    out = []
    for i, d in enumerate(A["dests"]):
        color = PALETTE[i % len(PALETTE)]
        for ts, route, _ in A["by_dest"][d["dest"]]:
            out.append(f'<circle cx="{x(ts):.1f}" cy="{y(len(route)):.1f}" r="2.5" fill="{color}" fill-opacity=".7" '
                       f'data-dest="{d["dest"]}" data-ts="{ts}">'
                       f'<title>{esc(fmt_ts(ts))} {esc(d["label"])}: {len(route)} hops</title></circle>')
    for v in (0, maxh):
        out.append(f'<text x="{L - 6}" y="{y(v) + 4:.1f}" text-anchor="end">{v}</text>')
    out.append(time_axis(A, L, R, H - 6, W))
    return svg(W, H, "".join(out))


def chart_changes(A, bucket=600):
    W, L, R, T, B, H = 960, 36, 12, 8, 22, 200
    nb = (A["t1"] - A["t0"]) // bucket + 1
    counts = [0] * nb
    for ts, *_ in A["events"]:
        counts[(ts - A["t0"]) // bucket] += 1
    peak = max(counts) or 1
    bw = (W - L - R) / nb
    out = []
    for i, c in enumerate(counts):
        h = c / peak * (H - T - B)
        start = A["t0"] + i * bucket
        out.append(f'<rect class="bar" x="{L + i * bw + 1:.1f}" y="{H - B - h:.1f}" '
                   f'width="{max(bw - 2, 1):.1f}" height="{h:.1f}"><title>{tlabel(start)}: '
                   f'{c} route change(s) in 10 min</title></rect>')
    out.append(f'<text x="{L - 6}" y="{T + 10}" text-anchor="end">{peak}</text>')
    out.append(time_axis(A, L, R, H - 6, W))
    return svg(W, H, "".join(out))


def chart_ips(A, top=25):
    dest_ids = set(A["labels"])
    rows = A["ip_hits"].most_common(top)
    W, LBL, R, ROW = 960, 190, 60, 22
    peak = rows[0][1] if rows else 1
    out = []
    for i, (h, c) in enumerate(rows):
        y = 4 + i * ROW
        w = c / peak * (W - LBL - R)
        name = fmt_ip(A["ips"][h]) + (" (destination)" if h in dest_ids else "")
        out.append(f'<text x="{LBL - 8}" y="{y + 15}" text-anchor="end">{esc(name)}</text>')
        out.append(f'<rect class="bar" x="{LBL}" y="{y + 3}" width="{w:.1f}" height="{ROW - 8}"/>')
        out.append(f'<text x="{LBL + w + 6:.1f}" y="{y + 15}">{c}</text>')
    return svg(W, 8 + ROW * len(rows), "".join(out))


def chart_heat(A):
    if not A["column"]:
        return '<p class="muted">No hops.</p>'
    dest_ids = set(A["labels"])
    ips_sorted = sorted(A["column"], key=lambda h: (A["column"][h], -A["ip_hits"][h]))
    grid = A["hop_grid"]
    maxh = max(i for (_, i) in grid)
    peak = max(grid.values())
    LBL, T, CW, RH = 190, 18, 26, 16
    W = LBL + maxh * CW + 10
    H = T + len(ips_sorted) * RH + 8
    out = []
    for i in range(1, maxh + 1, 2):
        out.append(f'<text x="{LBL + (i - 1) * CW}" y="{T - 5}">{i}</text>')
    for r, h in enumerate(ips_sorted):
        y = T + r * RH
        name = fmt_ip(A["ips"][h]) + (" (destination)" if h in dest_ids else "")
        out.append(f'<text x="{LBL - 8}" y="{y + 12}" text-anchor="end">{esc(name)}</text>')
        for i in range(1, maxh + 1):
            c = grid.get((h, i), 0)
            if c:
                out.append(f'<rect class="cell" x="{LBL + (i - 1) * CW}" y="{y}" width="{CW - 2}" '
                           f'height="{RH - 2}" fill-opacity="{0.15 + 0.85 * c / peak:.2f}">'
                           f'<title>{esc(name)} at hop {i}: {c} trace(s)</title></rect>')
    return svg(W, H, "".join(out))


def chart_map(A, tiles=None):
    """World map on OpenStreetMap tiles (Web Mercator). tiles = (zoom, {(x, y): data-uri}) or None."""
    z, images = tiles if tiles else (2, {})
    N = TILE * 2 ** z
    y_top = merc_xy(75, 0, z)[1]
    y_bot = merc_xy(-55, 0, z)[1]
    geo = A["geo"]

    def xy(h):
        g = geo.get(h) or {}
        if g.get("lat") is None or g.get("lon") is None:
            return None
        px, py = merc_xy(g["lat"], g["lon"], z)
        return px, py

    out = []
    for (x, y), uri in images.items():
        out.append(f'<image x="{x * TILE}" y="{y * TILE}" width="{TILE}" height="{TILE}" href="{uri}"/>')
    peak_e = max(A["edges"].values(), default=1)
    for (a, b), c in A["edges"].items():
        pa, pb = xy(a), xy(b)
        if pa and pb:
            out.append(f'<line x1="{pa[0]:.1f}" y1="{pa[1]:.1f}" x2="{pb[0]:.1f}" y2="{pb[1]:.1f}" '
                       f'stroke="#2a4d80" stroke-opacity=".55" stroke-width="{0.8 + 3 * c / peak_e:.2f}">'
                       f'<title>{esc(fmt_ip(A["ips"][a]))} → {esc(fmt_ip(A["ips"][b]))}: {c} trace(s)</title></line>')
    peak_h = max(A["ip_hits"].values(), default=1)
    dest_ids = set(A["labels"])
    for h, hits in A["ip_hits"].items():
        p = xy(h)
        if p is None:
            continue
        r = 4 + 7 * (hits / peak_h) ** 0.5
        fill = "#e15759" if h in dest_ids else "#4e79a7"
        out.append(f'<circle cx="{p[0]:.1f}" cy="{p[1]:.1f}" r="{r:.1f}" fill="{fill}" fill-opacity=".85" '
                   f'stroke="#fff" stroke-width="1">'
                   f'<title>{esc(fmt_ip(A["ips"][h]))} {esc(geo_place(A, h))}: {hits} trace(s)</title></circle>')
    out.append(f'<text x="{N - 6}" y="{y_bot - 6:.0f}" text-anchor="end" class="attrib">{esc(ATTRIBUTION)}</text>')
    return (f'<svg viewBox="0 {y_top:.0f} {N} {y_bot - y_top:.0f}" xmlns="http://www.w3.org/2000/svg">'
            f'{"".join(out)}</svg>')


FILTER_CSS = """
.filters{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 12px;margin-top:14px;display:flex;flex-wrap:wrap;gap:8px 18px;align-items:center;font-size:13px}
.filters .fgroup{display:flex;flex-wrap:wrap;gap:4px 10px;align-items:center}
.filters input[type=range]{width:220px;vertical-align:middle}
.filters button{font:inherit;padding:3px 10px;border-radius:6px;border:1px solid var(--line);background:var(--bg);color:var(--fg);cursor:pointer}
.hidden-by-filter{display:none}
"""

FILTER_JS = """
(function(){
  const filters = document.getElementById('filters');
  const boxes = [...filters.querySelectorAll('input[data-dest]')];
  const from = document.getElementById('fromT'), to = document.getElementById('toT');
  const fromL = document.getElementById('fromL'), toL = document.getElementById('toL');
  const count = document.getElementById('fcount');
  const fmt = s => new Date(s * 1000).toLocaleString();
  const marks = [...document.querySelectorAll('[data-dest]')].filter(el => !filters.contains(el));
  function apply(){
    let a = +from.value, b = +to.value;
    if (a > b) [a, b] = [b, a];
    fromL.textContent = fmt(a); toL.textContent = fmt(b);
    const on = new Set(boxes.filter(c => c.checked).map(c => c.dataset.dest));
    let shown = 0, total = 0;
    for (const el of marks) {
      const ts = el.dataset.ts;
      const ok = on.has(el.dataset.dest) && (ts === undefined || (+ts >= a && +ts <= b));
      el.classList.toggle('hidden-by-filter', !ok);
      if (el.classList.contains('change-row')) { total++; if (ok) shown++; }
    }
    count.textContent = total ? `${shown} of ${total} change rows shown` : '';
  }
  boxes.forEach(c => c.addEventListener('change', apply));
  [from, to].forEach(r => r.addEventListener('input', apply));
  document.getElementById('reset').addEventListener('click', () => {
    boxes.forEach(c => c.checked = true);
    from.value = from.min; to.value = to.max; apply();
  });
  apply();
})();
"""


def filter_html(A):
    lo, hi = A["t0"], A["t1"]
    boxes = "".join(
        f'<label><input type="checkbox" data-dest="{d["dest"]}" checked> '
        f'<i class="swatch" style="background:{PALETTE[i % len(PALETTE)]}"></i>{esc(d["label"])}</label>'
        for i, d in enumerate(A["dests"]))
    return (f'<div class="filters" id="filters">'
            f'<div class="fgroup"><span class="muted">Destinations</span>{boxes}</div>'
            f'<div class="fgroup"><label>From <input type="range" id="fromT" min="{lo}" max="{hi}" step="1" value="{lo}"></label>'
            f'<span id="fromL">{esc(fmt_ts(lo))}</span></div>'
            f'<div class="fgroup"><label>To <input type="range" id="toT" min="{lo}" max="{hi}" step="1" value="{hi}"></label>'
            f'<span id="toL">{esc(fmt_ts(hi))}</span></div>'
            f'<div class="fgroup"><button id="reset" type="button">Reset</button>'
            f'<span id="fcount" class="muted"></span></div>'
            f'</div><p class="muted">Filters hide table rows and chart marks in this page. '
            f'Summary cards and aggregate charts always show the full dataset.</p>')


GRAPH_MODE_JS = """
(function(){
  const sel = document.getElementById('unkMode');
  sel.addEventListener('change', () => {
    document.querySelectorAll('.gmode').forEach(d => d.hidden = d.dataset.mode !== sel.value);
  });
})();
"""


def graph_block(A):
    """Hop graph with a selector for unknown-hop display. All three versions are rendered; the page switches."""
    opts = "".join(f'<option value="{k}">{esc(label)}</option>' for k, label, _ in UNKNOWN_MODES)
    panes = "".join(f'<div class="gmode" data-mode="{k}"{"" if k == "show" else " hidden"}>'
                    f'<div class="wrap">{chart_graph(A, k)}</div>{table(*graph_table(A, k))}</div>'
                    for k, _, _ in UNKNOWN_MODES)
    return ('<p class="muted">Nodes are IPs, dashed grey nodes are unknown hops. Each column is the average '
            'position along the paths; edges are consecutive hops, thicker = more traces. An unknown run between '
            'the same IP on both sides is that IP; between two different IPs it is a separate unknown node. '
            'Hiding unknown hops links the known hops on either side directly.</p>'
            f'<div class="filters"><label>Unknown hops <select id="unkMode">{opts}</select></label></div>'
            f'{panes}<script>{GRAPH_MODE_JS}</script>')


def table(headers, rows, attrs=None):
    """attrs: optional per-row attribute strings (e.g. ' data-dest="1"') used by the filter script."""
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    attrs = attrs or [""] * len(rows)
    body = "".join(f"<tr{a}>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r, a in zip(rows, attrs))
    return f'<div class="wrap"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def render(A, db_path, tiles=None):
    ips = A["ips"]
    cards = [("Traces", A["n_traces"]), ("Destinations", len(A["dests"])), ("IPs seen", A["ip_count"]),
             ("Distinct routes", A["routes_total"]), ("Route changes", len(A["events"])),
             ("Time span", f'{(A["t1"] - A["t0"]) / 3600:.1f} h')]
    card_html = "".join(f'<div class="card"><span class="muted">{esc(k)}</span><b>{esc(v)}</b></div>'
                        for k, v in cards)

    legend = "".join(f'<span><i class="swatch" style="background:{PALETTE[i % len(PALETTE)]}"></i>'
                     f'{esc(d["label"])}</span>' for i, d in enumerate(A["dests"]))

    dest_rows = [[esc(d["label"]), esc(geo_place(A, d["dest"])), d["n"], f'{d["reached"]:.0%}', d["routes"],
                  d["changes"], d["no_reply"], f'{d["avg_hops"]:.1f}', f'{d["star_pct"]:.0%}',
                  esc(fmt_ts(d["first"])), esc(fmt_ts(d["last"]))] for d in A["dests"]]
    dest_attrs = [f' data-dest="{d["dest"]}"' for d in A["dests"]]

    geo_sections = []
    if A["geo"]:
        ip_rows = []
        for h, hits in A["ip_hits"].most_common():
            g = A["geo"].get(h) or {}
            ip_rows.append([esc(fmt_ip(ips[h])), hits, esc(geo_place(A, h)) or "–",
                            esc(g.get("asn") or "–"), esc(g.get("org") or "–"),
                            (f'{g["lat"]:.2f}, {g["lon"]:.2f}' if g.get("lat") is not None else "–")])
        asn_tot = collections.defaultdict(lambda: [set(), 0, ""])
        for h, hits in A["ip_hits"].items():
            g = A["geo"].get(h) or {}
            if g.get("asn"):
                entry = asn_tot[g["asn"]]
                entry[0].add(h)
                entry[1] += hits
                entry[2] = g.get("org") or ""
        asn_rows = [[esc(f"AS{asn}"), esc(org), len(hs), hits]
                    for asn, (hs, hits, org) in sorted(asn_tot.items(), key=lambda kv: -kv[1][1])]
        geo_sections = [
            ("World map", '<p class="muted">Located IPs (GeoLite2 City, approximate to city level). '
                          'Map tiles: OpenStreetMap, cached locally. '
                          'Red = destination. Lines = hop-to-hop links, thicker = more traces. '
                          'Private addresses have no location.</p>'
                          f'<div class="wrap">{chart_map(A, tiles)}</div>'),
            ("Locations & networks", table(["IP", "Traces", "Location", "ASN", "Organisation", "Lat, lon"], ip_rows)),
            ("Networks (ASN)", table(["ASN", "Organisation", "IPs", "Traces"], asn_rows)),
        ]

    var_rows, var_attrs = [], []
    for d in A["dests"]:
        for r, (cnt, first, last) in sorted(A["variants"][d["dest"]].items(), key=lambda kv: -kv[1][0]):
            var_rows.append([f'<i class="swatch" style="background:{route_color(r)}"></i>{esc(d["label"])}',
                             cnt, esc(fmt_ts(first)), esc(fmt_ts(last)),
                             f'<span class="route">{esc(route_str(ips, r))}</span>'])
            var_attrs.append(f' data-dest="{d["dest"]}"')

    ev_limit = 500
    ev_rows = [[esc(fmt_ts(ts)), esc(A["labels"][dest]), len(prev), len(r),
                f'<span class="route">{esc(route_str(ips, prev))}</span>',
                f'<span class="route">{esc(route_str(ips, r))}</span>']
               for ts, dest, prev, r in A["events"][:ev_limit]]
    ev_attrs = [f' class="change-row" data-dest="{dest}" data-ts="{ts}"' for ts, dest, _, _ in A["events"][:ev_limit]]
    ev_note = (f'<p class="muted">Showing first {ev_limit} of {len(A["events"])} changes. '
               'A change is a consecutive trace to the same destination whose non-* hops differ.</p>'
               if len(A["events"]) > ev_limit else
               '<p class="muted">A change is a consecutive trace to the same destination whose non-* hops differ.</p>')

    sections = [
        ("Destinations", table(["Destination", "Location", "Traces", "Reached", "Routes", "Changes", "No reply",
                                "Avg hops", "* hops", "First", "Last"], dest_rows, dest_attrs)),
        ("Route timeline", '<p class="muted">Each dot is one traceroute. Colour is the route (non-* hops); '
                           'a colour change along a row is a route change. Grey = no replies.</p>'
                           f'<div class="wrap">{chart_timeline(A)}</div>'),
        ("Hop count over time", f'<div class="legend">{legend}</div>'
                                f'<div class="wrap">{chart_hops(A)}</div>'),
        ("Route changes over time", '<p class="muted">Route changes per 10 minutes.</p>'
                                    f'<div class="wrap">{chart_changes(A)}</div>'),
        ("Most seen IPs", '<p class="muted">Traces each IP appeared in.</p>'
                          f'<div class="wrap">{chart_ips(A)}</div>'),
        ("IP × hop position", '<p class="muted">How often each IP appears at each hop number. '
                              'Rows are sorted by average position.</p>'
                              f'<div class="wrap">{chart_heat(A)}</div>'),
        ("Hop graph", graph_block(A)),
        ("Route variants", table(["Destination", "Traces", "First", "Last", "Route"], var_rows, var_attrs)),
        ("Route change log", ev_note + table(["Time", "Destination", "Hops before", "Hops after",
                                              "From", "To"], ev_rows, ev_attrs)),
    ]
    sections[1:1] = geo_sections  # right after Destinations
    sec_html = "".join(f"<section><h2>{esc(t)}</h2>{body}</section>" for t, body in sections)
    now = dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    return (f'<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>Traceroute report</title><style>{STYLE}{FILTER_CSS}</style></head><body><main>'
            f'<h1>Traceroute report</h1>'
            f'<p class="muted">Source: {esc(db_path)} · generated {now}</p>'
            f'<div class="cards">{card_html}</div>{filter_html(A)}{sec_html}</main>'
            f'<script>{FILTER_JS}</script></body></html>')


def add_tile_args(ap):
    ap.add_argument("--map-zoom", type=int, default=2, choices=range(0, 5),
                    help="OSM zoom for the world map (default 2 = 16 tiles)")
    ap.add_argument("--tile-cache", default=str(HERE / "tile_cache"))
    ap.add_argument("--no-tiles", action="store_true", help="draw the map without OpenStreetMap tiles")


def load_tiles(args):
    """(zoom, {(x, y): data-uri}) for the report, or None. Downloads only tiles missing from the cache."""
    if args.no_tiles:
        return None
    paths = fetch_world(args.map_zoom, args.tile_cache)
    return args.map_zoom, {k: data_uri(p) for k, p in paths.items()}


def main():
    ap = argparse.ArgumentParser(description="Render traceroute.db as an HTML report.")
    ap.add_argument("--db", default=str(HERE.parent / "traceroute" / "traceroute.db"))
    ap.add_argument("--out", default=str(HERE / "report.html"))
    ap.add_argument("--geo-dir", default=str(HERE.parent / "traceroute"))
    add_tile_args(ap)
    args = ap.parse_args()

    try:
        A = build(args.db, args.geo_dir)
    except ValueError as e:
        sys.exit(str(e))
    Path(args.out).write_text(render(A, args.db, load_tiles(args)), encoding="utf-8")
    print(f"{A['n_traces']} traces, {len(A['dests'])} destinations, "
          f"{len(A['events'])} route changes -> {args.out}")


if __name__ == "__main__":
    main()
