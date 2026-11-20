#!/usr/bin/env python3
"""traceviz GTK 4 app: tables, world map and route timeline for traceroute.db.

Header bar: destination and time-window filters, reload. Needs PyGObject with GTK 4
(system python3 on Arch: python-gobject, gtk4). The optional GeoIP lookups need maxminddb,
so run it with a venv created using --system-site-packages.
"""
import argparse
import colorsys
import math
import sys
from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gio, Gtk  # noqa: E402

import cairo  # noqa: E402

import traceviz as tv  # noqa: E402
from tiles import ATTRIBUTION, TILE, fetch_world, merc_xy  # noqa: E402

WINDOWS = [None, 3600, 1800, 600]
WINDOW_NAMES = ["all time", "last 1h", "last 30m", "last 10m"]
BG = (0.98, 0.98, 0.97)
FG = (0.12, 0.12, 0.11)
ACCENT = (0.31, 0.47, 0.65)
DEST_RED = (0.88, 0.35, 0.35)


def route_rgb(route):
    if not route:
        return (0.54, 0.54, 0.52)
    return colorsys.hls_to_rgb(tv.route_hue(route) / 360, 0.5, 0.65)


def sort_key(s):
    try:
        return (0, float(s.rstrip("%")))
    except ValueError:
        return (1, s)


def sort_cmp(model, a, b, col):
    ka, kb = sort_key(model[a][col]), sort_key(model[b][col])
    return (ka > kb) - (ka < kb)


def load_tile_surfaces(opts):
    """Cairo surfaces for the world tiles at opts['zoom'], fetched into opts['cache'] only when missing."""
    if not opts["enabled"]:
        return {}
    paths = fetch_world(opts["zoom"], opts["cache"])
    return {k: cairo.ImageSurface.create_from_png(str(p)) for k, p in paths.items()}


class TraceWindow(Gtk.ApplicationWindow):
    def __init__(self, app, db, geo_dir, tile_opts):
        super().__init__(application=app, title="Traceroute viewer", default_width=1100, default_height=760)
        self.db, self.geo_dir = db, geo_dir
        self.zoom = tile_opts["zoom"]
        self.tile_surfaces = load_tile_surfaces(tile_opts)
        self.dest_idx = -1
        self.win_idx = 0
        self.unk_idx = 0
        self.A = None
        self.full = tv.build(db, geo_dir)  # unfiltered load: destination list and time bounds

        bar = Gtk.HeaderBar()
        self.dest_drop = Gtk.DropDown.new_from_strings(
            ["All destinations"] + [d["label"] for d in self.full["dests"]])
        self.dest_drop.connect("notify::selected", self.on_filter_changed)
        self.win_drop = Gtk.DropDown.new_from_strings(WINDOW_NAMES)
        self.win_drop.connect("notify::selected", self.on_filter_changed)
        self.unk_drop = Gtk.DropDown.new_from_strings([label for _, label, _ in tv.UNKNOWN_MODES])
        self.unk_drop.set_tooltip_text("Unknown (*) hops in the graph")
        self.unk_drop.connect("notify::selected", self.on_filter_changed)
        reload_btn = Gtk.Button(icon_name="view-refresh-symbolic", tooltip_text="Reload database")
        reload_btn.connect("clicked", self.on_reload)
        bar.pack_start(self.dest_drop)
        bar.pack_start(self.win_drop)
        bar.pack_start(self.unk_drop)
        bar.pack_end(reload_btn)
        self.set_titlebar(bar)

        self.notebook = Gtk.Notebook(vexpand=True)
        self.status = Gtk.Label(xalign=0, margin_start=10, margin_end=10, margin_top=4, margin_bottom=4)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        box.append(self.notebook)
        box.append(self.status)
        self.set_child(box)
        self.refresh()

    def on_filter_changed(self, *_):
        self.dest_idx = self.dest_drop.get_selected() - 1
        self.win_idx = self.win_drop.get_selected()
        self.unk_idx = self.unk_drop.get_selected()
        self.refresh()

    def on_reload(self, *_):
        self.full = tv.build(self.db, self.geo_dir)
        self.refresh()

    def refresh(self):
        dests = None if self.dest_idx < 0 else {self.full["dests"][self.dest_idx]["dest"]}
        w = WINDOWS[self.win_idx]
        t0 = None if w is None else self.full["t1"] - w
        try:
            self.A = tv.build(self.db, self.geo_dir, dests=dests, t0=t0)
        except ValueError as e:
            self.status.set_text(str(e))  # keep the previous pages on screen
            return
        A = self.A
        self.status.set_text(f"{A['n_traces']} traces · {len(A['dests'])} destinations · "
                             f"{len(A['events'])} route changes")
        while self.notebook.get_n_pages():
            self.notebook.remove_page(-1)
        self.add_table("Destinations", tv.dest_table(A))
        self.add_drawing("World map", self.draw_map)
        self.add_drawing("Route timeline", self.draw_timeline)
        self.add_drawing("Hop graph", self.draw_graph)
        self.add_table("Graph nodes", tv.graph_table(A, self.unk_mode()))
        self.add_table("Routes", tv.route_table(A))
        self.add_table("Changes", tv.change_table(A))
        self.add_table("IPs", tv.ip_table(A))

    def add_table(self, title, data):
        headers, rows = data
        store = Gtk.ListStore(*([str] * len(headers)))
        for r in rows:
            store.append(r)
        for i in range(len(headers)):
            store.set_sort_func(i, sort_cmp, i)
        view = Gtk.TreeView(model=store)
        for i, hd in enumerate(headers):
            col = Gtk.TreeViewColumn(hd, Gtk.CellRendererText(), text=i)
            col.set_resizable(True)
            col.set_sort_column_id(i)
            view.append_column(col)
        sw = Gtk.ScrolledWindow(vexpand=True)
        sw.set_child(view)
        self.notebook.append_page(sw, Gtk.Label(label=title))

    def add_drawing(self, title, draw_fn):
        area = Gtk.DrawingArea(hexpand=True, vexpand=True)
        area.set_content_width(900)
        area.set_content_height(480)
        area.set_draw_func(lambda _a, cr, w, h: draw_fn(cr, w, h))
        sw = Gtk.ScrolledWindow(vexpand=True)
        sw.set_child(area)
        self.notebook.append_page(sw, Gtk.Label(label=title))

    @staticmethod
    def paint(cr, w, h):
        cr.set_source_rgb(*BG)
        cr.paint()

    def draw_map(self, cr, w, h):
        """World map: OpenStreetMap tiles (Web Mercator) with located IPs and hop links on top."""
        A = self.A
        self.paint(cr, w, h)
        z = self.zoom
        N = TILE * 2 ** z
        y_top, y_bot = merc_xy(75, 0, z)[1], merc_xy(-55, 0, z)[1]
        s = min(w / N, h / (y_bot - y_top))
        ox = (w - N * s) / 2

        def proj(lat, lon):
            px, py = merc_xy(lat, lon, z)
            return ox + px * s, (py - y_top) * s

        for (tx, ty), surf in self.tile_surfaces.items():
            cr.save()
            cr.translate(ox + tx * TILE * s, (ty * TILE - y_top) * s)
            cr.scale(s, s)
            cr.set_source_surface(surf, 0, 0)
            cr.rectangle(0, 0, TILE, TILE)
            cr.fill()
            cr.restore()

        def xy(hid):
            g = A["geo"].get(hid) or {}
            if g.get("lat") is None or g.get("lon") is None:
                return None
            return proj(g["lat"], g["lon"])

        peak_e = max(A["edges"].values(), default=1)
        for (a, b), c in A["edges"].items():
            pa, pb = xy(a), xy(b)
            if pa and pb:
                cr.set_source_rgba(0.16, 0.30, 0.50, 0.55)
                cr.set_line_width(0.8 + 3 * c / peak_e)
                cr.move_to(*pa)
                cr.line_to(*pb)
                cr.stroke()

        peak_h = max(A["ip_hits"].values(), default=1)
        dest_ids = set(A["labels"])
        for hid, hits in A["ip_hits"].items():
            p = xy(hid)
            if p is None:
                continue
            cr.set_source_rgb(*(DEST_RED if hid in dest_ids else ACCENT))
            cr.arc(p[0], p[1], 4 + 7 * math.sqrt(hits / peak_h), 0, 2 * math.pi)
            cr.fill()
        cr.set_font_size(10)
        cr.set_source_rgb(*FG)
        cr.move_to(w - 260, h - 8)
        cr.show_text(ATTRIBUTION)
        if not A["geo"]:
            cr.move_to(12, 24)
            cr.show_text("No GeoIP data: run with the maxminddb venv and the .mmdb files.")

    def unk_mode(self):
        return tv.UNKNOWN_MODES[self.unk_idx][0]

    def draw_graph(self, cr, w, h):
        """Layered hop graph: columns = average position, edges = consecutive hops (width = traces)."""
        G = tv.graph_for(self.A, self.unk_mode())
        self.paint(cr, w, h)
        layers = tv.graph_layers(G)
        if not layers:
            return
        M = 40
        maxrows = max(len(layer) for layer in layers)
        CW = max(120, (w - 2 * M) / len(layers))
        RH = max(40, (h - 2 * M) / maxrows)
        pos = {}
        for x, layer in enumerate(layers):
            top = M + (maxrows - len(layer)) * RH / 2
            for y, k in enumerate(layer):
                pos[k] = (M + x * CW + CW / 2, top + y * RH + RH / 2)
        peak = max(G["edges"].values(), default=1)
        cr.set_source_rgba(0.5, 0.5, 0.5, 0.6)
        for (a, b), c in G["edges"].items():
            cr.set_line_width(1 + 3 * c / peak)
            cr.move_to(*pos[a])
            cr.line_to(*pos[b])
            cr.stroke()
        cr.set_font_size(11)
        for k, (x, y) in pos.items():
            n = G["nodes"][k]
            if n["kind"] == "unknown":
                cr.set_source_rgb(*FG)
                cr.set_dash([3, 2])
                cr.arc(x, y, 9, 0, 2 * math.pi)
                cr.stroke()
                cr.set_dash([])
            else:
                cr.set_source_rgb(*(DEST_RED if n["kind"] == "dest" else ACCENT))
                cr.arc(x, y, 9, 0, 2 * math.pi)
                cr.fill()
            cr.set_source_rgb(*FG)
            cr.move_to(x + 12, y + 4)
            cr.show_text(n["short"])
            sub = " ".join(str(v) for v in (f'AS{n["asn"]}' if n["asn"] else "", n["country"] or "") if v)
            if sub:
                cr.move_to(x + 12, y + 16)
                cr.show_text(sub)

    def draw_timeline(self, cr, w, h):
        A = self.A
        self.paint(cr, w, h)
        L, R, T, B = 110, 12, 10, 26
        dests = A["dests"]
        rowh = (h - T - B) / max(len(dests), 1)
        span = max(A["t1"] - A["t0"], 1)
        cr.set_font_size(11)
        for i, d in enumerate(dests):
            y = T + i * rowh + rowh / 2
            cr.set_source_rgb(*FG)
            cr.move_to(6, y + 4)
            cr.show_text(d["label"])
            cr.set_source_rgba(0.5, 0.5, 0.5, 0.25)
            cr.move_to(L, y)
            cr.line_to(w - R, y)
            cr.stroke()
            for ts, _, r in A["by_dest"][d["dest"]]:
                x = L + (ts - A["t0"]) / span * (w - L - R)
                cr.set_source_rgb(*route_rgb(r))
                cr.arc(x, y, 3, 0, 2 * math.pi)
                cr.fill()
        cr.set_source_rgb(*FG)
        cr.move_to(L, h - 8)
        cr.show_text(tv.tlabel(A["t0"]))
        cr.move_to(w - R - 40, h - 8)
        cr.show_text(tv.tlabel(A["t1"]))


class TraceApp(Gtk.Application):
    def __init__(self, db, geo_dir, tile_opts):
        super().__init__(application_id="dev.traceviz.app", flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self.db, self.geo_dir, self.tile_opts = db, geo_dir, tile_opts

    def do_activate(self):
        TraceWindow(self, self.db, self.geo_dir, self.tile_opts).present()


def main():
    ap = argparse.ArgumentParser(description="GTK viewer for traceroute.db.")
    ap.add_argument("--db", default=str(tv.HERE.parent / "traceroute" / "traceroute.db"))
    ap.add_argument("--geo-dir", default=str(tv.HERE.parent / "traceroute"))
    tv.add_tile_args(ap)
    args = ap.parse_args()
    if not Path(args.db).exists():
        sys.exit(f"database not found: {args.db}")
    tile_opts = {"enabled": not args.no_tiles, "zoom": args.map_zoom, "cache": args.tile_cache}
    sys.exit(TraceApp(args.db, args.geo_dir, tile_opts).run([sys.argv[0]]))


if __name__ == "__main__":
    main()
