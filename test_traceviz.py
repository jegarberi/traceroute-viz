"""Self-check: python3 test_traceviz.py  (or pytest)."""
import os
import sqlite3
import tempfile

from traceviz import analyze, fmt_ip, graph_layers, load, render


def make_db(path):
    con = sqlite3.connect(path)
    con.executescript("""
        CREATE TABLE ips (id INTEGER PRIMARY KEY, ip INTEGER UNIQUE NOT NULL);
        CREATE TABLE paths (path_id INTEGER PRIMARY KEY, path TEXT UNIQUE);
        CREATE TABLE tracerts (id INTEGER PRIMARY KEY, ip_destination_id INTEGER NOT NULL,
                               path_id INTEGER NOT NULL, ts TIMESTAMP NOT NULL);
    """)
    # 10.0.0.1, * (no reply), 8.8.8.8 (destination), 10.0.0.2
    con.executemany("INSERT INTO ips VALUES (?,?)", [(1, 167772161), (2, 0), (3, 134744072), (4, 167772162)])
    con.executemany("INSERT INTO paths VALUES (?,?)", [(1, "1,2,3"), (2, "1,3"), (3, "1,4,3")])
    con.executemany("INSERT INTO tracerts (ip_destination_id, path_id, ts) VALUES (3, ?, ?)",
                    [(1, 100), (2, 200), (3, 300), (3, 400)])
    con.commit()
    con.close()


def test_ip_decoding():
    assert fmt_ip(3232261377) == "192.168.101.1"
    assert fmt_ip(0) == "*"


def test_route_change_ignores_star_only_differences():
    with tempfile.TemporaryDirectory() as d:
        db = os.path.join(d, "t.db")
        make_db(db)
        ips, paths, traces = load(db)
        A = analyze(ips, paths, traces)
    # raw paths differ at ts 100->200 (a * dropped) but the real route is the same,
    # so only the 200->300 switch to 10.0.0.2 counts.
    dest = A["dests"][0]
    assert dest["changes"] == 1, dest
    assert dest["routes"] == 2, dest
    assert dest["reached"] == 1.0, dest
    assert A["events"][0][0] == 300


def test_render_contains_charts():
    with tempfile.TemporaryDirectory() as d:
        db = os.path.join(d, "t.db")
        make_db(db)
        ips, paths, traces = load(db)
        page = render(analyze(ips, paths, traces), db)
    assert page.count("<svg") == 8  # timeline, hops, changes, ips, heat, 3 graph modes
    assert "8.8.8.8" in page


def test_geo_sections_render_with_lookup():
    with tempfile.TemporaryDirectory() as d:
        db = os.path.join(d, "t.db")
        make_db(db)
        ips, paths, traces = load(db)
        geo = {
            1: {"private": True, "country": None, "city": None, "lat": None, "lon": None, "asn": None, "org": None},
            3: {"private": False, "country": "US", "city": "Mountain View", "lat": 37.4, "lon": -122.1,
                "asn": 15169, "org": "Google LLC"},
            4: {"private": False, "country": "AR", "city": "Buenos Aires", "lat": -34.6, "lon": -58.4,
                "asn": 16701, "org": "ARCA"},
        }
        page = render(analyze(ips, paths, traces, geo), db)
    assert page.count("<svg") == 9  # + world map
    assert "AS15169" in page and "Google LLC" in page
    assert "Mountain View, US" in page
    assert "private" in page


def test_unknown_hop_rules():
    from traceviz import route_sequence
    star = lambda h: h == 0  # id 0 stands for "*" in these tests
    assert route_sequence([1, 0, 1], star) == [1]                 # same IP either side: absorbed
    assert route_sequence([1, 0, 2], star) == [1, ("*", 1, 2), 2]  # different IPs: separate unknown node
    assert route_sequence([0, 2], star) == [("*", None, 2), 2]     # leading stars
    assert route_sequence([1, 0], star) == [1, ("*", 1, None)]     # trailing stars
    assert route_sequence([0, 0], star) == []                      # nothing known
    assert route_sequence([1, 0, 0, 2], star) == [1, ("*", 1, 2), 2]  # a run of stars counts once


def test_graph_builds_nodes_and_edges():
    with tempfile.TemporaryDirectory() as d:
        db = os.path.join(d, "t.db")
        make_db(db)
        ips, paths, traces = load(db)
        A = analyze(ips, paths, traces)
    G = A["graph"]
    # paths: "1,2,3" (* between 1 and 3 = unknown node), "1,3", "1,4,3" (x2)
    assert G["edges"][(1, 4)] == 2 and G["edges"][(4, 3)] == 2 and G["edges"][(1, 3)] == 1
    assert G["edges"][(1, ("*", 1, 3))] == 1 and G["edges"][(("*", 1, 3), 3)] == 1
    assert G["nodes"][("*", 1, 3)]["kind"] == "unknown"
    assert G["nodes"][3]["kind"] == "dest" and G["nodes"][3]["hits"] == 4
    layers = graph_layers(G)
    assert layers[0] == [1] and 3 in layers[-1]  # node 3 averages position 2.5 and shares a layer with 4


def test_tile_cache_downloads_each_tile_once():
    import urllib.request
    import tiles

    calls = []

    class FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b"\x89PNG fake"

    real_urlopen, real_interval = urllib.request.urlopen, tiles.MIN_INTERVAL
    urllib.request.urlopen = lambda req, timeout=None: (calls.append(req.full_url), FakeResp())[1]
    tiles.MIN_INTERVAL = 0
    try:
        with tempfile.TemporaryDirectory() as d:
            first = tiles.get_tile(1, 0, 1, d)
            second = tiles.get_tile(1, 0, 1, d)
            assert first == second and first.exists()
            assert calls == ["https://tile.openstreetmap.org/1/0/1.png"], calls  # second read came from disk
            assert tiles.get_tile(1, 0, 0, d, fetch=False) is None and len(calls) == 1
    finally:
        urllib.request.urlopen, tiles.MIN_INTERVAL = real_urlopen, real_interval


def test_mercator_projection_and_tile_markup():
    from tiles import merc_xy
    assert merc_xy(0, 0, 0) == (128, 128)
    x, y = merc_xy(0, 180, 1)
    assert abs(x - 512) < 1e-9 and abs(y - 256) < 1e-9
    with tempfile.TemporaryDirectory() as d:
        db = os.path.join(d, "t.db")
        make_db(db)
        ips, paths, traces = load(db)
        geo = {3: {"private": False, "country": "US", "city": None, "lat": 37.4, "lon": -122.1,
                   "asn": 15169, "org": "Google LLC"}}
        A = analyze(ips, paths, traces, geo)
        page = render(A, db, tiles=(0, {(0, 0): "data:image/png;base64,AA=="}))
    assert '<image x="0" y="0"' in page and "OpenStreetMap" in page


def test_worldmap_land_and_view():
    import worldmap
    from tiles import merc_xy
    land = worldmap.Land.from_tiles(os.path.join(os.path.dirname(os.path.abspath(__file__)), "tile_cache"),
                                    fetch=False)
    if land is None:
        print("skip: no cached tiles for the world map")
        return
    assert land.is_land(*merc_xy(-34.6, -58.4, worldmap.ZOOM))  # Buenos Aires
    assert not land.is_land(*merc_xy(-30, -130, worldmap.ZOOM))  # South Pacific
    v = worldmap.View()
    v.zoom_by(2)
    assert v.span_x() == worldmap.world_size() / 4
    assert v.cell(0, 0, 80, 20) is None or isinstance(v.cell(0, 0, 80, 20), tuple)


def test_unknown_hop_display_modes():
    from traceviz import route_sequence
    star = lambda h: h == 0
    assert route_sequence([1, 0, 0, 2], star, min_hide=2) == [1, 2]     # run of 2 hidden, neighbours linked
    assert route_sequence([1, 0, 2], star, min_hide=2) == [1, ("*", 1, 2), 2]  # single * kept
    assert route_sequence([1, 0, 2], star, min_hide=1) == [1, 2]        # hide all
    assert route_sequence([0, 0, 2], star, min_hide=2) == [2]           # leading run hidden


def test_graph_modes_differ():
    with tempfile.TemporaryDirectory() as d:
        db = os.path.join(d, "t.db")
        make_db(db)
        ips, paths, traces = load(db)
        A = analyze(ips, paths, traces)
    from traceviz import graph_for
    shown = graph_for(A, "show")["nodes"]
    hidden = graph_for(A, "hide-all")["nodes"]
    assert any(isinstance(k, tuple) for k in shown)
    assert not any(isinstance(k, tuple) for k in hidden)


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok", name)
