package main

// Port of traceviz.py's analysis (load, analyze, build_graph, route_sequence) so the web
// report shows the same numbers as the GTK viewer.

import (
	"crypto/md5"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

const noReplyIP = 0 // ips.ip == 0 is the "*" hop

// counter is a map counter that remembers first-insertion order (like a Python dict/Counter).
type counter[K comparable] struct {
	keys []K
	m    map[K]int
}

func newCounter[K comparable]() *counter[K] { return &counter[K]{m: map[K]int{}} }

func (c *counter[K]) add(k K, n int) {
	if _, ok := c.m[k]; !ok {
		c.keys = append(c.keys, k)
	}
	c.m[k] += n
}

func (c *counter[K]) get(k K) int { return c.m[k] }

func (c *counter[K]) peak() int {
	p := 1
	for _, v := range c.m {
		if v > p {
			p = v
		}
	}
	return p
}

// mostCommon returns the keys by descending count; ties keep insertion order.
func (c *counter[K]) mostCommon() []K {
	out := append([]K(nil), c.keys...)
	sort.SliceStable(out, func(i, j int) bool { return c.m[out[i]] > c.m[out[j]] })
	return out
}

type rawTrace struct {
	ts, dest, pid int64
}

// raw is the unfiltered database content.
type raw struct {
	ips     map[int64]uint32
	paths   map[int64][]int64
	traces  []rawTrace // ORDER BY ts, id
	ipCount int
}

func loadRaw(db *sql.DB) (*raw, error) {
	r := &raw{ips: map[int64]uint32{}, paths: map[int64][]int64{}}
	rows, err := db.Query(`SELECT id, ip FROM ips`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id, ip int64
		if err := rows.Scan(&id, &ip); err != nil {
			rows.Close()
			return nil, err
		}
		r.ips[id] = uint32(ip)
		if uint32(ip) != noReplyIP {
			r.ipCount++
		}
	}
	rows.Close()

	rows, err = db.Query(`SELECT path_id, path FROM paths`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var pid int64
		var p sql.NullString
		if err := rows.Scan(&pid, &p); err != nil {
			rows.Close()
			return nil, err
		}
		var hops []int64
		for _, h := range strings.Split(p.String, ",") {
			if h == "" {
				continue
			}
			v, err := strconv.ParseInt(h, 10, 64)
			if err != nil {
				rows.Close()
				return nil, err
			}
			hops = append(hops, v)
		}
		r.paths[pid] = hops
	}
	rows.Close()

	rows, err = db.Query(`SELECT ts, ip_destination_id, path_id FROM tracerts ORDER BY ts, id`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var t rawTrace
		if err := rows.Scan(&t.ts, &t.dest, &t.pid); err != nil {
			rows.Close()
			return nil, err
		}
		r.traces = append(r.traces, t)
	}
	rows.Close()
	return r, rows.Err()
}

// filter mirrors build(): optional destination and earliest-timestamp bounds.
type filter struct {
	dest    int64
	hasDest bool
	t0      int64
	hasT0   bool
}

type item struct {
	ts   int64
	raw  []int64 // hops as recorded (may include *)
	real []int64 // non-* hops
	key  string  // encoded real route
}

type destStat struct {
	dest                      int64
	label                     string
	n                         int
	first, last               int64
	routes, changes, noReply  int
	reached, avgHops, starPct float64
}

type variant struct {
	route       []int64
	count       int
	first, last int64
}

type event struct {
	ts, dest  int64
	prev, cur []int64
}

type analysis struct {
	ips       map[int64]uint32
	labels    map[int64]string
	dests     []destStat // ascending dest id
	destOrder []int64    // first-seen order (python dict order of by_dest)
	byDest    map[int64][]item
	variants  map[int64]*varSet
	events    []event
	ipHits    *counter[int64]
	edges     *counter[[2]int64]
	geo       map[int64]*geoRec
	t0, t1    int64
	nTraces   int
	ipCount   int
	routesTot int
	graph     *graph
	graphs    map[int]*graph // by min-hide length
}

type varSet struct {
	order []string
	m     map[string]*variant
}

func encodeRoute(route []int64) string {
	parts := make([]string, len(route))
	for i, h := range route {
		parts[i] = strconv.FormatInt(h, 10)
	}
	return strings.Join(parts, ",")
}

// reprRoute matches Python's repr() of a tuple of ints, which the GTK app hashes for route colours.
func reprRoute(route []int64) string {
	parts := make([]string, len(route))
	for i, h := range route {
		parts[i] = strconv.FormatInt(h, 10)
	}
	switch len(parts) {
	case 0:
		return "()"
	case 1:
		return "(" + parts[0] + ",)"
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

func routeHue(route []int64) int {
	sum := md5.Sum([]byte(reprRoute(route)))
	v, _ := strconv.ParseUint(hex.EncodeToString(sum[:3]), 16, 32)
	return int(v % 360)
}

func (r *raw) fmtIP(id int64) string { return fmtIP(r.ips[id]) }

func fmtIP(ip uint32) string {
	if ip == noReplyIP {
		return "*"
	}
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, ip)
	return net.IP(b).String()
}

func fmtTS(ts int64) string { return time.Unix(ts, 0).Format("2006-01-02 15:04:05") }

func tlabel(ts int64) string { return time.Unix(ts, 0).Format("15:04") }

// routeStr is " → " joined hop addresses, or "(no replies)".
func routeStr(ips map[int64]uint32, route []int64) string {
	if len(route) == 0 {
		return "(no replies)"
	}
	parts := make([]string, len(route))
	for i, h := range route {
		parts[i] = fmtIP(ips[h])
	}
	return strings.Join(parts, " → ")
}

func analyze(r *raw, f filter, geo map[int64]*geoRec) (*analysis, error) {
	traces := make([]rawTrace, 0, len(r.traces))
	for _, t := range r.traces {
		if f.hasDest && t.dest != f.dest {
			continue
		}
		if f.hasT0 && t.ts < f.t0 {
			continue
		}
		traces = append(traces, t)
	}
	if len(traces) == 0 {
		return nil, fmt.Errorf("no traces match the filter")
	}

	isStar := func(h int64) bool { return r.ips[h] == noReplyIP }
	A := &analysis{
		ips: r.ips, labels: map[int64]string{}, byDest: map[int64][]item{},
		variants: map[int64]*varSet{}, ipHits: newCounter[int64](), edges: newCounter[[2]int64](),
		geo: geo, t0: traces[0].ts, t1: traces[len(traces)-1].ts, nTraces: len(traces),
		ipCount: r.ipCount, graphs: map[int]*graph{},
	}

	destIDs := map[int64]bool{}
	for _, t := range traces {
		if !destIDs[t.dest] {
			destIDs[t.dest] = true
			A.destOrder = append(A.destOrder, t.dest)
		}
		route := r.paths[t.pid]
		var realR []int64
		for _, h := range route {
			if !isStar(h) {
				realR = append(realR, h)
			}
		}
		A.byDest[t.dest] = append(A.byDest[t.dest], item{ts: t.ts, raw: route, real: realR, key: encodeRoute(realR)})
	}

	sortedDests := append([]int64(nil), A.destOrder...)
	sort.Slice(sortedDests, func(i, j int) bool { return sortedDests[i] < sortedDests[j] })

	allRoutes := map[string]bool{}
	for _, dest := range sortedDests {
		items := A.byDest[dest]
		A.labels[dest] = fmtIP(r.ips[dest])
		vs := &varSet{m: map[string]*variant{}}
		A.variants[dest] = vs
		var prev []int64
		var prevKey string
		hasPrev := false
		var changes, reached, noReply, hops, stars int
		for _, it := range items {
			v, ok := vs.m[it.key]
			if ok {
				v.count++
				v.last = it.ts
			} else {
				v = &variant{route: it.real, count: 1, first: it.ts, last: it.ts}
				vs.m[it.key] = v
				vs.order = append(vs.order, it.key)
			}
			allRoutes[it.key] = true
			if hasPrev && it.key != prevKey {
				changes++
				A.events = append(A.events, event{ts: it.ts, dest: dest, prev: prev, cur: it.real})
			}
			prev, prevKey, hasPrev = it.real, it.key, true
			if n := len(it.raw); n > 0 && it.raw[n-1] == dest {
				reached++
			}
			if len(it.real) == 0 {
				noReply++
			}
			hops += len(it.raw)
			for _, h := range it.raw {
				if isStar(h) {
					stars++
				}
			}
		}
		n := len(items)
		d := destStat{
			dest: dest, label: A.labels[dest], n: n, first: items[0].ts, last: items[n-1].ts,
			routes: len(vs.m), changes: changes, noReply: noReply,
			reached: float64(reached) / float64(n), avgHops: float64(hops) / float64(n),
		}
		if hops > 0 {
			d.starPct = float64(stars) / float64(hops)
		}
		A.dests = append(A.dests, d)
	}
	A.routesTot = len(allRoutes)

	for _, dest := range A.destOrder {
		for _, it := range A.byDest[dest] {
			seen := map[int64]bool{}
			for _, h := range it.raw {
				if !isStar(h) && !seen[h] {
					seen[h] = true
					A.ipHits.add(h, 1)
				}
			}
			for i := 0; i+1 < len(it.raw); i++ {
				a, b := it.raw[i], it.raw[i+1]
				if a != b && !isStar(a) && !isStar(b) {
					A.edges.add([2]int64{a, b}, 1)
				}
			}
		}
	}

	A.graph = buildGraph(A, 0)
	return A, nil
}

// ---- hop graph -------------------------------------------------------------

// nodeKey is an IP id, or an unknown-hop run (star) with the known hops on either side.
type nodeKey struct {
	star                bool
	id                  int64
	before, after       int64
	hasBefore, hasAfter bool
}

type nodeInfo struct {
	key                 nodeKey
	label, short, kind  string
	place, org, country string
	asn                 uint
	col, hits           int
}

type edgeKey struct{ a, b nodeKey }

type graph struct {
	nodes     map[nodeKey]*nodeInfo
	nodeOrder []nodeKey
	edges     *counter[edgeKey]
}

// unknownModes matches UNKNOWN_MODES in traceviz.py: key, label, minimum run length to hide (0 = keep all).
var unknownModes = []struct {
	key, label string
	minHide    int
}{
	{"show", "show all *", 0},
	{"hide-multi", "hide runs of 2+ *", 2},
	{"hide-all", "hide all *", 1},
}

// routeSequence collapses a raw route into graph node keys (see route_sequence in traceviz.py).
func routeSequence(route []int64, isStar func(int64) bool, minHide int) []nodeKey {
	var seq []nodeKey
	var prev int64
	hasPrev := false
	n := len(route)
	for i := 0; i < n; {
		if !isStar(route[i]) {
			k := nodeKey{id: route[i]}
			if len(seq) == 0 || seq[len(seq)-1] != k {
				seq = append(seq, k)
			}
			prev, hasPrev = route[i], true
			i++
			continue
		}
		j := i
		for j < n && isStar(route[j]) {
			j++
		}
		nxt, hasNxt := int64(0), j < n
		if hasNxt {
			nxt = route[j]
		}
		sameIP := hasPrev && hasNxt && prev == nxt
		hidden := minHide > 0 && j-i >= minHide
		if !sameIP && !hidden && (hasPrev || hasNxt) {
			seq = append(seq, nodeKey{star: true, before: prev, hasBefore: hasPrev, after: nxt, hasAfter: hasNxt})
		}
		i = j
	}
	return seq
}

func (A *analysis) nodeInfo(k nodeKey) *nodeInfo {
	if k.star {
		var label string
		switch {
		case !k.hasBefore:
			label = fmt.Sprintf("* (before %s)", fmtIP(A.ips[k.after]))
		case !k.hasAfter:
			label = fmt.Sprintf("* (after %s)", fmtIP(A.ips[k.before]))
		default:
			label = fmt.Sprintf("* (between %s and %s)", fmtIP(A.ips[k.before]), fmtIP(A.ips[k.after]))
		}
		return &nodeInfo{key: k, label: label, short: "*", kind: "unknown"}
	}
	g := A.geo[k.id]
	ni := &nodeInfo{key: k, short: fmtIP(A.ips[k.id]), label: fmtIP(A.ips[k.id]), kind: "ip"}
	if _, ok := A.labels[k.id]; ok {
		ni.kind = "dest"
	}
	ni.place = A.geoPlace(k.id)
	if g != nil {
		ni.asn, ni.org, ni.country = g.ASN, g.Org, g.Country
	}
	return ni
}

func buildGraph(A *analysis, minHide int) *graph {
	isStar := func(h int64) bool { return A.ips[h] == noReplyIP }
	G := &graph{nodes: map[nodeKey]*nodeInfo{}, edges: newCounter[edgeKey]()}
	posSum, posN, hits := map[nodeKey]int{}, map[nodeKey]int{}, map[nodeKey]int{}
	for _, dest := range A.destOrder {
		for _, it := range A.byDest[dest] {
			seq := routeSequence(it.raw, isStar, minHide)
			for i, k := range seq {
				if _, ok := G.nodes[k]; !ok {
					G.nodes[k] = A.nodeInfo(k)
					G.nodeOrder = append(G.nodeOrder, k)
				}
				posSum[k] += i + 1
				posN[k]++
			}
			uniq := map[nodeKey]bool{}
			for _, k := range seq {
				uniq[k] = true
			}
			for k := range uniq {
				hits[k]++
			}
			for i := 0; i+1 < len(seq); i++ {
				if seq[i] != seq[i+1] {
					G.edges.add(edgeKey{seq[i], seq[i+1]}, 1)
				}
			}
		}
	}
	for k, info := range G.nodes {
		info.col = int(math.RoundToEven(float64(posSum[k]) / float64(posN[k])))
		info.hits = hits[k]
	}
	return G
}

func (A *analysis) graphFor(mode string) *graph {
	minHide := 0
	for _, m := range unknownModes {
		if m.key == mode {
			minHide = m.minHide
		}
	}
	if minHide == 0 {
		return A.graph
	}
	if g, ok := A.graphs[minHide]; ok {
		return g
	}
	g := buildGraph(A, minHide)
	A.graphs[minHide] = g
	return g
}

// layers groups nodes into columns by average position; busiest node first in each column.
func (G *graph) layers() [][]nodeKey {
	colSet := map[int]bool{}
	for _, n := range G.nodes {
		colSet[n.col] = true
	}
	var cols []int
	for c := range colSet {
		cols = append(cols, c)
	}
	sort.Ints(cols)
	out := make([][]nodeKey, 0, len(cols))
	for _, c := range cols {
		var layer []nodeKey
		for _, k := range G.nodeOrder {
			if G.nodes[k].col == c {
				layer = append(layer, k)
			}
		}
		sort.SliceStable(layer, func(i, j int) bool { return G.nodes[layer[i]].hits > G.nodes[layer[j]].hits })
		out = append(out, layer)
	}
	return out
}

// ---- helpers used by the renderer -----------------------------------------

func (A *analysis) geoPlace(id int64) string {
	g := A.geo[id]
	if g == nil {
		return ""
	}
	if g.Private {
		if g.CGNAT {
			return "CGNAT (shared)"
		}
		return "private"
	}
	var parts []string
	if g.City != "" {
		parts = append(parts, g.City)
	}
	if g.Country != "" {
		parts = append(parts, g.Country)
	}
	if len(parts) == 0 {
		return "unknown"
	}
	return strings.Join(parts, ", ")
}

func (A *analysis) routeColor(route []int64) string {
	if len(route) == 0 {
		return "#8a8a85"
	}
	return fmt.Sprintf("hsl(%d 65%% 50%%)", routeHue(route))
}
