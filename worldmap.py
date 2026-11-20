"""ASCII world map for the TUI, with zoom and pan.

Land and sea come from the cached OpenStreetMap zoom-2 tiles (see tiles.py), so no extra data is
downloaded. In OSM's style water is bluish and land is not, which gives a land/sea mask. The mask is
built once per run and sampled for every terminal cell. Requires pycairo (to read the PNGs).

The view is a window in world pixels (Web Mercator, ZOOM=2 world = 1024 px wide). Zoom halves the
window width per step. Terminal character cells are assumed to be about twice as tall as wide, so
the window height follows the number of rows and the map keeps its proportions.
"""
import math

import cairo

from tiles import TILE, fetch_world, merc_xy

ZOOM = 2  # world pixel grid used for the mask (1024 px wide)
GRID = 4  # world pixels per mask cell
MAX_ZOOM = 4
WATER_MARGIN = 25  # a pixel is water when blue exceeds red by this much (OSM water #aad3df, land #f2efe9)


def world_size():
    return TILE * 2 ** ZOOM


class Land:
    def __init__(self, cells, n):
        self.cells = cells  # bytearray, 1 = land
        self.n = n  # mask width and height in cells

    @classmethod
    def from_tiles(cls, cache, fetch=True):
        paths = fetch_world(ZOOM, cache, fetch)
        if len(paths) < 4 ** ZOOM:
            return None  # incomplete world: no reliable mask
        per_tile = TILE // GRID
        n = per_tile * 2 ** ZOOM
        cells = bytearray(n * n)
        for (tx, ty), path in paths.items():
            surf = cairo.ImageSurface.create_from_png(str(path))
            data, stride = surf.get_data(), surf.get_stride()
            for cy in range(per_tile):
                for cx in range(per_tile):
                    o = (cy * GRID + GRID // 2) * stride + (cx * GRID + GRID // 2) * 4
                    b, r = data[o], data[o + 2]  # cairo stores BGRA
                    if b - r <= WATER_MARGIN:
                        cells[(ty * per_tile + cy) * n + tx * per_tile + cx] = 1
        return cls(cells, n)

    def is_land(self, x, y):
        gx, gy = int(x // GRID), int(y // GRID)
        if not (0 <= gx < self.n and 0 <= gy < self.n):
            return False
        return self.cells[gy * self.n + gx] == 1


def inverse_merc(x, y):
    """World pixel (ZOOM grid) back to (lat, lon)."""
    N = world_size()
    lon = x / N * 360 - 180
    lat = math.degrees(math.atan(math.sinh(math.pi * (1 - 2 * y / N))))
    return lat, lon


class View:
    """Window on the world: centre (cx, cy) in world pixels and a zoom level (0 = whole world wide)."""

    def __init__(self):
        self.zoom = 0
        self.cx = world_size() / 2
        self.cy = merc_xy(30, 0, ZOOM)[1]  # start around the northern mid-latitudes

    def span_x(self):
        return world_size() / 2 ** self.zoom

    def span_y(self, cols, rows):
        return self.span_x() * rows * 2 / cols

    def _clamp(self):
        N = world_size()
        self.cx %= N
        self.cy = min(max(self.cy, 0), N)

    def zoom_by(self, step):
        self.zoom = min(MAX_ZOOM, max(0, self.zoom + step))
        self._clamp()

    def pan(self, dx, dy, cols, rows):
        """Move by a fraction of the window: dx, dy in -1..1 (positive = right / down)."""
        self.cx += dx * self.span_x()
        self.cy += dy * self.span_y(cols, rows)
        self._clamp()

    def reset(self):
        self.__init__()

    def grid(self, land, cols, rows):
        """rows x cols list of chars: '#' land, ' ' sea."""
        N = world_size()
        sx, sy = self.span_x(), self.span_y(cols, rows)
        x0, y0 = self.cx - sx / 2, self.cy - sy / 2
        out = []
        for r in range(rows):
            y = y0 + (r + 0.5) / rows * sy
            line = []
            for c in range(cols):
                x = (x0 + (c + 0.5) / cols * sx) % N
                line.append("#" if land and 0 <= y < N and land.is_land(x, y) else " ")
            out.append(line)
        return out

    def cell(self, lat, lon, cols, rows):
        """(row, col) on this view for a lat/lon, or None if it is outside the view."""
        N = world_size()
        x, y = merc_xy(lat, lon, ZOOM)
        sx, sy = self.span_x(), self.span_y(cols, rows)
        dx = (x - self.cx + N / 2) % N - N / 2  # shortest way round the world
        c = int((dx + sx / 2) / sx * cols)
        r = int((y - (self.cy - sy / 2)) / sy * rows)
        if 0 <= c < cols and 0 <= r < rows:
            return r, c
        return None

    def describe(self):
        lat, lon = inverse_merc(self.cx, self.cy)
        return f"zoom {2 ** self.zoom}x  centre {abs(lat):.1f}{'N' if lat >= 0 else 'S'} " \
               f"{abs(lon):.1f}{'E' if lon >= 0 else 'W'}"
