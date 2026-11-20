#!/usr/bin/env python3
"""traceviz TUI: browse traceroute.db in a terminal (curses).

  1-6 / Tab / Shift-Tab   switch view (Destinations, Routes, Changes, IPs, Graph, Map)
  j/k, arrows, PgUp/PgDn, g/G   move (in lists)
  Map view: + / - zoom, arrows or h/j/k/l pan, 0 reset
  d   cycle destination filter      w   cycle time window (all, 1h, 30m, 10m)
  u   cycle unknown-hop display (show all *, hide runs of 2+ *, hide all *) for the Graph view
  r   reload the database           q   quit

Lists use the stdlib only. The Map view needs pycairo to read the cached OSM tiles for the land mask.
"""
import argparse
import curses
import sys
from pathlib import Path

import traceviz as tv
import worldmap

VIEWS = [("Destinations", tv.dest_table), ("Routes", tv.route_table),
         ("Changes", tv.change_table), ("IPs", tv.ip_table), ("Graph", tv.graph_table),
         ("Map", None)]  # None = the ASCII world map, drawn separately
WINDOWS = [None, 3600, 1800, 600]
WINDOW_NAMES = ["all time", "last 1h", "last 30m", "last 10m"]
PAN_KEYS = {curses.KEY_LEFT: (-1, 0), ord("h"): (-1, 0), curses.KEY_RIGHT: (1, 0), ord("l"): (1, 0),
            curses.KEY_UP: (0, -1), ord("k"): (0, -1), curses.KEY_DOWN: (0, 1), ord("j"): (0, 1)}
PAN_STEP = 0.25
C_LAND, C_IP, C_DEST = 1, 2, 3


class State:
    """Filter state. dest_idx -1 means all destinations; the time window is relative to the newest trace."""

    def __init__(self, db, geo_dir, land):
        self.db, self.geo_dir = db, geo_dir
        self.dest_idx = -1
        self.win_idx = 0
        self.unk_idx = 0
        self.error = ""
        self.land = land  # worldmap.Land or None when tiles are unavailable
        self.view = worldmap.View()
        self.map_size = (80, 20)
        self.full = tv.build(db, geo_dir)
        self.A = self.full

    def apply(self):
        dests = None if self.dest_idx < 0 else {self.full["dests"][self.dest_idx]["dest"]}
        w = WINDOWS[self.win_idx]
        t0 = None if w is None else self.full["t1"] - w
        try:
            self.A = tv.build(self.db, self.geo_dir, dests=dests, t0=t0)
            self.error = ""
        except ValueError as e:
            self.A = None
            self.error = str(e)

    def reload(self):
        self.full = tv.build(self.db, self.geo_dir)
        self.apply()

    def cycle_dest(self):
        self.dest_idx = -1 if self.dest_idx + 1 >= len(self.full["dests"]) else self.dest_idx + 1
        self.apply()

    def cycle_window(self):
        self.win_idx = (self.win_idx + 1) % len(WINDOWS)
        self.apply()

    def cycle_unknown(self):
        self.unk_idx = (self.unk_idx + 1) % len(tv.UNKNOWN_MODES)

    def unk_mode(self):
        return tv.UNKNOWN_MODES[self.unk_idx][0]

    def dest_name(self):
        return "all" if self.dest_idx < 0 else self.full["dests"][self.dest_idx]["label"]


def col_widths(headers, rows, avail):
    nat = [min(40, max([len(h)] + [len(r[i]) for r in rows])) for i, h in enumerate(headers)]
    while sum(nat) + 2 * (len(nat) - 1) > avail and max(nat) > 6:
        nat[nat.index(max(nat))] -= 1
    return nat


def table_for(st, view):
    name, fn = VIEWS[view]
    if name == "Graph":
        return tv.graph_table(st.A, st.unk_mode())
    return fn(st.A)


def attr(pair):
    return curses.color_pair(pair) if curses.has_colors() else curses.A_BOLD


def draw_map(scr, st, h, w):
    cols, rows = max(10, w - 1), max(4, h - 5)
    st.map_size = (cols, rows)
    scr.addnstr(2, 0, f"{st.view.describe()}   +/- zoom  arrows/hjkl pan  0 reset", w - 1, curses.A_DIM)
    if st.land is None:
        scr.addnstr(3, 0, "no map data: OSM tiles are not cached (run once online, or drop --no-tiles)",
                    w - 1, curses.A_BOLD)
        shown = 0
    else:
        for r, line in enumerate(st.view.grid(st.land, cols, rows)):
            scr.addnstr(3 + r, 0, "".join(line), w - 1, attr(C_LAND))
        marks = []
        for hid, hits in st.A["ip_hits"].items():
            g = st.A["geo"].get(hid) or {}
            if g.get("lat") is None or g.get("lon") is None:
                continue
            cell = st.view.cell(g["lat"], g["lon"], cols, rows)
            if cell:
                is_dest = hid in st.A["labels"]
                marks.append((is_dest, cell, hid))
        for is_dest, (r, c), hid in sorted(marks):  # IPs first, destinations drawn on top
            scr.addnstr(3 + r, c, "D" if is_dest else "o", 1, attr(C_DEST if is_dest else C_IP))
        shown = len(marks)
    located = sum(1 for hid in st.A["ip_hits"] if (st.A["geo"].get(hid) or {}).get("lat") is not None)
    scr.addnstr(h - 2, 0, f"#=land  o=IP  D=destination  ({shown} of {located} located IPs in view)  "
                          f"Map: (c) OpenStreetMap contributors", w - 1, curses.A_DIM)


def draw(scr, st, view, sel, top):
    """Draw one frame. Returns the number of table rows that fit on screen."""
    scr.erase()
    h, w = scr.getmaxyx()
    x = 0
    for i, (name, _) in enumerate(VIEWS):
        label = f" {i + 1} {name} "
        scr.addnstr(0, x, label, max(0, w - x - 1), curses.A_REVERSE if i == view else curses.A_NORMAL)
        x += len(label) + 1
    n = st.A["n_traces"] if st.A else 0
    scr.addnstr(1, 0, f"destination: {st.dest_name()}   window: {WINDOW_NAMES[st.win_idx]}   "
                      f"unknown hops: {tv.UNKNOWN_MODES[st.unk_idx][1]}   traces: {n}",
                w - 1, curses.A_DIM)
    page = max(1, h - 6)
    if VIEWS[view][1] is None:
        if st.A is not None:
            draw_map(scr, st, h, w)
        scr.addnstr(h - 1, 0, "1-6 views  +/- zoom  arrows/hjkl pan  0 reset  d destination  w window  "
                              "r reload  q quit", w - 1, curses.A_DIM)
    elif st.A is None:
        scr.addnstr(3, 0, st.error, w - 1, curses.A_BOLD)
    else:
        headers, rows = table_for(st, view)
        widths = col_widths(headers, rows, w - 1)

        def line(cells):
            return "  ".join(c[:wd].ljust(wd) for c, wd in zip(cells, widths))

        scr.addnstr(2, 0, line(headers), w - 1, curses.A_BOLD | curses.A_UNDERLINE)
        if not rows:
            scr.addnstr(3, 0, "(no rows)", w - 1)
        for i in range(page):
            idx = top + i
            if idx >= len(rows):
                break
            scr.addnstr(3 + i, 0, line(rows[idx]), w - 1,
                        curses.A_REVERSE if idx == sel else curses.A_NORMAL)
        if rows:
            scr.addnstr(h - 2, 0, " | ".join(rows[sel]), w - 1, curses.A_DIM)
            pos = f"  row {sel + 1}/{len(rows)}"
        else:
            pos = ""
        scr.addnstr(h - 1, 0, f"1-{len(VIEWS)} views  j/k move  d destination  w window  u unknown hops  r reload  q quit" + pos,
                    w - 1, curses.A_DIM)
    scr.refresh()
    return page


def handle_map_key(ch, st):
    """Zoom and pan keys for the map view. Returns True if the key was used."""
    if ch in (ord("+"), ord("=")):
        st.view.zoom_by(1)
    elif ch == ord("-"):
        st.view.zoom_by(-1)
    elif ch == ord("0"):
        st.view.reset()
    elif ch in PAN_KEYS:
        dx, dy = PAN_KEYS[ch]
        cols, rows = st.map_size
        st.view.pan(dx * PAN_STEP, dy * PAN_STEP, cols, rows)
    else:
        return False
    return True


def run(scr, st):
    curses.curs_set(0)
    if curses.has_colors():
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(C_LAND, curses.COLOR_GREEN, -1)
        curses.init_pair(C_IP, curses.COLOR_YELLOW, -1)
        curses.init_pair(C_DEST, curses.COLOR_RED, -1)
    view = sel = top = 0
    page = 1
    while True:
        is_map = VIEWS[view][1] is None
        rows = [] if is_map or st.A is None else table_for(st, view)[1]
        sel = min(sel, max(len(rows) - 1, 0))
        if sel < top:
            top = sel
        if sel >= top + page:
            top = sel - page + 1
        page = draw(scr, st, view, sel, top)

        ch = scr.getch()
        if is_map and handle_map_key(ch, st):
            continue
        if ch in (ord("q"), ord("Q"), 27):
            break
        elif ch in (9, curses.KEY_RIGHT):
            view, sel, top = (view + 1) % len(VIEWS), 0, 0
        elif ch in (curses.KEY_BTAB, curses.KEY_LEFT):
            view, sel, top = (view - 1) % len(VIEWS), 0, 0
        elif ord("1") <= ch <= ord("0") + len(VIEWS):
            view, sel, top = ch - ord("1"), 0, 0
        elif ch in (ord("j"), curses.KEY_DOWN):
            sel = min(sel + 1, max(len(rows) - 1, 0))
        elif ch in (ord("k"), curses.KEY_UP):
            sel = max(sel - 1, 0)
        elif ch == curses.KEY_NPAGE:
            sel = min(sel + page, max(len(rows) - 1, 0))
        elif ch == curses.KEY_PPAGE:
            sel = max(sel - page, 0)
        elif ch == ord("g"):
            sel = 0
        elif ch == ord("G"):
            sel = max(len(rows) - 1, 0)
        elif ch == ord("d"):
            st.cycle_dest()
            sel = top = 0
        elif ch == ord("w"):
            st.cycle_window()
            sel = top = 0
        elif ch == ord("u"):
            st.cycle_unknown()
        elif ch == ord("r"):
            st.reload()


def main():
    ap = argparse.ArgumentParser(description="Browse traceroute.db in a terminal.")
    ap.add_argument("--db", default=str(tv.HERE.parent / "traceroute" / "traceroute.db"))
    ap.add_argument("--geo-dir", default=str(tv.HERE.parent / "traceroute"))
    ap.add_argument("--tile-cache", default=str(tv.HERE / "tile_cache"))
    ap.add_argument("--no-tiles", action="store_true", help="no land mask for the Map view (no network)")
    args = ap.parse_args()
    if not Path(args.db).exists():
        sys.exit(f"database not found: {args.db}")
    land = None if args.no_tiles else worldmap.Land.from_tiles(args.tile_cache)
    try:
        st = State(args.db, args.geo_dir, land)
    except ValueError as e:
        sys.exit(str(e))
    curses.wrapper(run, st)


if __name__ == "__main__":
    main()
