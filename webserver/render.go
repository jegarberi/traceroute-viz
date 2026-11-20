package main

// HTML/SVG rendering of the GTK viewer's tabs: Destinations, World map, Route timeline,
// Hop graph, Graph nodes, Routes, Changes and IPs.

import (
	"fmt"
	"html"
	"math"
	"sort"
	"strings"
)

const (
	tileSize = 256
	tileURL  = "https://tile.openstreetmap.org/%d/%d/%d.png"
	attrib   = "© OpenStreetMap contributors"
	accent   = "#4e79a7"
)

func esc(s string) string { return html.EscapeString(s) }

func dash(s string) string {
	if s == "" {
		return "–"
	}
	return s
}

func svgWrap(w, h float64, body string) string {
	return fmt.Sprintf(`<svg viewBox="0 0 %.0f %.0f" xmlns="http://www.w3.org/2000/svg">%s</svg>`, w, h, body)
}

// htmlTable renders already-escaped cells.
func htmlTable(head []string, rows [][]string) string {
	var b strings.Builder
	b.WriteString(`<div class="wrap"><table><thead><tr>`)
	for _, h := range head {
		b.WriteString("<th>" + esc(h) + "</th>")
	}
	b.WriteString("</tr></thead><tbody>")
	for _, r := range rows {
		b.WriteString("<tr>")
		for _, c := range r {
			b.WriteString("<td>" + c + "</td>")
		}
		b.WriteString("</tr>")
	}
	b.WriteString("</tbody></table></div>")
	return b.String()
}

// ---- tables (dest_table, route_table, change_table, ip_table, graph_table) ----

func (A *analysis) destTable() string {
	head := []string{"Destination", "Location", "Traces", "Reached", "Routes", "Changes", "No reply",
		"Avg hops", "* hops", "First", "Last"}
	var rows [][]string
	for _, d := range A.dests {
		rows = append(rows, []string{esc(d.label), esc(A.geoPlace(d.dest)), fmt.Sprint(d.n),
			fmt.Sprintf("%.0f%%", d.reached*100), fmt.Sprint(d.routes), fmt.Sprint(d.changes),
			fmt.Sprint(d.noReply), fmt.Sprintf("%.1f", d.avgHops), fmt.Sprintf("%.0f%%", d.starPct*100),
			esc(fmtTS(d.first)), esc(fmtTS(d.last))})
	}
	return htmlTable(head, rows)
}

// sortedVariants lists a destination's routes by descending trace count (stable).
func (A *analysis) sortedVariants(dest int64) []*variant {
	vs := A.variants[dest]
	out := make([]*variant, 0, len(vs.order))
	for _, k := range vs.order {
		out = append(out, vs.m[k])
	}
	sortStableByCount(out)
	return out
}

func sortStableByCount(vs []*variant) {
	sort.SliceStable(vs, func(i, j int) bool { return vs[i].count > vs[j].count })
}

func (A *analysis) routesTable() string {
	head := []string{"Destination", "Traces", "First", "Last", "Route"}
	var rows [][]string
	for _, d := range A.dests {
		for _, v := range A.sortedVariants(d.dest) {
			rows = append(rows, []string{
				`<i class="swatch" style="background:` + A.routeColor(v.route) + `"></i>` + esc(d.label),
				fmt.Sprint(v.count), esc(fmtTS(v.first)), esc(fmtTS(v.last)),
				`<span class="route">` + esc(routeStr(A.ips, v.route)) + `</span>`})
		}
	}
	return htmlTable(head, rows)
}

func (A *analysis) changesTable() string {
	head := []string{"Time", "Destination", "Hops before", "Hops after", "From", "To"}
	var rows [][]string
	for _, e := range A.events {
		rows = append(rows, []string{esc(fmtTS(e.ts)), esc(A.labels[e.dest]), fmt.Sprint(len(e.prev)),
			fmt.Sprint(len(e.cur)), `<span class="route">` + esc(routeStr(A.ips, e.prev)) + `</span>`,
			`<span class="route">` + esc(routeStr(A.ips, e.cur)) + `</span>`})
	}
	return htmlTable(head, rows)
}

func (A *analysis) ipTable() string {
	head := []string{"IP", "Traces", "Location", "ASN", "Organisation", "Lat", "Lon"}
	var rows [][]string
	for _, h := range A.ipHits.mostCommon() {
		g := A.geo[h]
		asn, org, lat, lon := "–", "–", "–", "–"
		if g != nil {
			if g.ASN != 0 {
				asn = fmt.Sprint(g.ASN)
			}
			org = dash(g.Org)
			if g.Lat != nil {
				lat = fmt.Sprintf("%.2f", *g.Lat)
			}
			if g.Lon != nil {
				lon = fmt.Sprintf("%.2f", *g.Lon)
			}
		}
		rows = append(rows, []string{esc(fmtIP(A.ips[h])), fmt.Sprint(A.ipHits.get(h)),
			esc(dash(A.geoPlace(h))), esc(asn), esc(org), lat, lon})
	}
	return htmlTable(head, rows)
}

func (A *analysis) graphTable(mode string) string {
	G := A.graphFor(mode)
	head := []string{"Layer", "Node", "Traces", "ASN", "Organisation", "Location", "Next hops (traces)"}
	var rows [][]string
	for x, layer := range G.layers() {
		for _, k := range layer {
			n := G.nodes[k]
			type nxt struct {
				b nodeKey
				c int
			}
			var next []nxt
			for _, ek := range G.edges.keys {
				if ek.a == k {
					next = append(next, nxt{ek.b, G.edges.get(ek)})
				}
			}
			sort.SliceStable(next, func(i, j int) bool { return next[i].c > next[j].c })
			var parts []string
			for _, t := range next {
				parts = append(parts, fmt.Sprintf("%s (%d)", G.nodes[t.b].short, t.c))
			}
			asn := "–"
			if n.asn != 0 {
				asn = fmt.Sprint(n.asn)
			}
			rows = append(rows, []string{fmt.Sprint(x + 1), esc(n.label), fmt.Sprint(n.hits), esc(asn),
				esc(dash(n.org)), esc(dash(n.place)), esc(dash(strings.Join(parts, ", ")))})
		}
	}
	return htmlTable(head, rows)
}

// ---- charts -----------------------------------------------------------------

func (A *analysis) timelineSVG() string {
	W, L, R, T, ROW := 960.0, 110.0, 12.0, 8.0, 26.0
	span := math.Max(float64(A.t1-A.t0), 1)
	H := T + ROW*float64(len(A.dests)) + 24
	x := func(ts int64) float64 { return L + float64(ts-A.t0)/span*(W-L-R) }
	var b strings.Builder
	for i, d := range A.dests {
		y := T + float64(i)*ROW + ROW/2
		fmt.Fprintf(&b, `<line class="grid" x1="%.0f" x2="%.0f" y1="%.1f" y2="%.1f"/>`, L, W-R, y, y)
		fmt.Fprintf(&b, `<text x="%.0f" y="%.1f" text-anchor="end">%s</text>`, L-8, y+4, esc(d.label))
		for _, it := range A.byDest[d.dest] {
			tip := fmt.Sprintf("%s → %s: %s", fmtTS(it.ts), d.label, routeStr(A.ips, it.real))
			fmt.Fprintf(&b, `<circle cx="%.1f" cy="%.1f" r="3" fill="%s"><title>%s</title></circle>`,
				x(it.ts), y, A.routeColor(it.real), esc(tip))
		}
	}
	b.WriteString(A.timeAxis(L, R, H-6, W))
	return svgWrap(W, H, b.String())
}

func (A *analysis) timeAxis(L, R, y, W float64) string {
	return fmt.Sprintf(`<text x="%.0f" y="%.0f">%s</text><text x="%.0f" y="%.0f" text-anchor="end">%s</text>`,
		L, y, tlabel(A.t0), W-R, y, tlabel(A.t1))
}

func (A *analysis) mapSVG(z int) string {
	N := float64(tileSize) * math.Pow(2, float64(z))
	_, yTop := mercXY(75, 0, z)
	_, yBot := mercXY(-55, 0, z)
	var b strings.Builder
	side := 1 << z
	for tx := 0; tx < side; tx++ {
		for ty := 0; ty < side; ty++ {
			fmt.Fprintf(&b, `<image x="%d" y="%d" width="%d" height="%d" href="`+tileURL+`"/>`,
				tx*tileSize, ty*tileSize, tileSize, tileSize, z, tx, ty)
		}
	}
	xy := func(id int64) (float64, float64, bool) {
		g := A.geo[id]
		if g == nil || g.Lat == nil || g.Lon == nil {
			return 0, 0, false
		}
		px, py := mercXY(*g.Lat, *g.Lon, z)
		return px, py, true
	}
	peakE := 1
	for _, c := range A.edges.m {
		if c > peakE {
			peakE = c
		}
	}
	for _, e := range A.edges.keys {
		ax, ay, okA := xy(e[0])
		bx, by, okB := xy(e[1])
		if okA && okB {
			c := A.edges.get(e)
			fmt.Fprintf(&b, `<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="#2a4d80" stroke-opacity=".55" stroke-width="%.2f"><title>%s → %s: %d trace(s)</title></line>`,
				ax, ay, bx, by, 0.8+3*float64(c)/float64(peakE),
				esc(fmtIP(A.ips[e[0]])), esc(fmtIP(A.ips[e[1]])), c)
		}
	}
	peakH := float64(A.ipHits.peak())
	for _, h := range A.ipHits.keys {
		px, py, ok := xy(h)
		if !ok {
			continue
		}
		r := 4 + 7*math.Sqrt(float64(A.ipHits.get(h))/peakH)
		fill := accent
		if _, isDest := A.labels[h]; isDest {
			fill = "#e15759"
		}
		fmt.Fprintf(&b, `<circle cx="%.1f" cy="%.1f" r="%.1f" fill="%s" fill-opacity=".85" stroke="#fff" stroke-width="1"><title>%s %s: %d trace(s)</title></circle>`,
			px, py, r, fill, esc(fmtIP(A.ips[h])), esc(A.geoPlace(h)), A.ipHits.get(h))
	}
	fmt.Fprintf(&b, `<text x="%.0f" y="%.0f" text-anchor="end" class="attrib">%s</text>`, N-6, yBot-6, esc(attrib))
	return fmt.Sprintf(`<svg viewBox="0 %.0f %.0f %.0f" xmlns="http://www.w3.org/2000/svg"><rect x="0" y="%.0f" width="%.0f" height="%.0f" fill="#dfe8ef"/>%s</svg>`,
		yTop, N, yBot-yTop, yTop, N, yBot-yTop, b.String())
}

// mercXY is Web Mercator world-pixel coordinates at zoom z.
func mercXY(lat, lon float64, z int) (float64, float64) {
	n := float64(tileSize) * math.Pow(2, float64(z))
	lat = math.Max(math.Min(lat, 85.0511), -85.0511)
	x := (lon + 180) / 360 * n
	s := math.Sin(lat * math.Pi / 180)
	y := (0.5 - math.Log((1+s)/(1-s))/(4*math.Pi)) * n
	return x, y
}

func (A *analysis) graphSVG(mode string) string {
	G := A.graphFor(mode)
	if len(G.nodes) == 0 {
		return `<p class="muted">No hops.</p>`
	}
	layers := G.layers()
	CW, RH, M := 170.0, 62.0, 40.0
	maxrows := 0
	for _, l := range layers {
		if len(l) > maxrows {
			maxrows = len(l)
		}
	}
	W := 2*M + float64(len(layers))*CW
	H := 2*M + float64(maxrows)*RH
	pos := map[nodeKey][2]float64{}
	for x, layer := range layers {
		top := M + float64(maxrows-len(layer))*RH/2
		for y, k := range layer {
			pos[k] = [2]float64{M + float64(x)*CW + CW/2, top + float64(y)*RH + RH/2}
		}
	}
	peak := G.edges.peak()
	var b strings.Builder
	for _, e := range G.edges.keys {
		pa, pb := pos[e.a], pos[e.b]
		c := G.edges.get(e)
		fmt.Fprintf(&b, `<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="var(--muted)" stroke-opacity=".6" stroke-width="%.2f"><title>%s → %s: %d trace(s)</title></line>`,
			pa[0], pa[1], pb[0], pb[1], 1+3*float64(c)/float64(peak),
			esc(G.nodes[e.a].label), esc(G.nodes[e.b].label), c)
	}
	for _, k := range G.nodeOrder {
		p := pos[k]
		n := G.nodes[k]
		fill := "var(--accent)"
		switch n.kind {
		case "dest":
			fill = "#e15759"
		case "unknown":
			fill = "none"
		}
		dash := ""
		if n.kind == "unknown" {
			dash = ` stroke-dasharray="3 2" stroke="var(--muted)" stroke-width="1.5"`
		}
		fmt.Fprintf(&b, `<circle cx="%.1f" cy="%.1f" r="9" fill="%s"%s><title>%s · %s · %s · %d trace(s)</title></circle>`,
			p[0], p[1], fill, dash, esc(n.label), esc(placeOr(n.place)), esc(n.org), n.hits)
		fmt.Fprintf(&b, `<text x="%.1f" y="%.1f" text-anchor="middle">%s</text>`, p[0], p[1]+24, esc(n.short))
		var sub []string
		if n.asn != 0 {
			sub = append(sub, fmt.Sprintf("AS%d", n.asn))
		}
		if n.country != "" {
			sub = append(sub, n.country)
		}
		if len(sub) > 0 {
			fmt.Fprintf(&b, `<text x="%.1f" y="%.1f" text-anchor="middle" class="muted-txt">%s</text>`,
				p[0], p[1]+37, esc(strings.Join(sub, " ")))
		}
	}
	return svgWrap(W, H, b.String())
}

func placeOr(s string) string {
	if s == "" {
		return "no location"
	}
	return s
}
