// traceviz-web: serve the traceroute.db report as tabs, mirroring the GTK viewer (gtk_app.py).
// Read-only: the database is opened with mode=ro.
//
// Filters are query parameters, like the GTK header bar:
//
//	/?dest=<ip id>&window=<seconds, 0 = all time>&unk=show|hide-multi|hide-all
package main

import (
	"bytes"
	"database/sql"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"path/filepath"
	"strconv"
	"time"

	_ "modernc.org/sqlite"
)

var defaultDB = "/home/jon/CLionProjects/traceroute/traceroute.db"

var windowOptions = []struct {
	secs  int64
	label string
}{{0, "all time"}, {3600, "last 1h"}, {1800, "last 30m"}, {600, "last 10m"}}

type option struct {
	Value, Label string
	Selected     bool
}

type card struct{ Label, Value string }

type tab struct {
	ID, Title string
	Body      template.HTML
}

type pageData struct {
	Source, Generated string
	DestOpts          []option
	WindowOpts        []option
	UnkOpts           []option
	Status, Error     string
	Cards             []card
	Tabs              []tab
	CSS               template.CSS
	JS                template.JS
}

func parseID(q string) (int64, bool) {
	if q == "" {
		return 0, false
	}
	v, err := strconv.ParseInt(q, 10, 64)
	return v, err == nil
}

type server struct {
	db     *sql.DB
	dbPath string
	geo    *geoReaders
	zoom   int
}

func (s *server) handle(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path != "/" {
		http.NotFound(w, req)
		return
	}
	raw, err := loadRaw(s.db)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	q := req.URL.Query()

	// Destination and window choices, relative to the unfiltered data (as the GTK header does).
	destIDs := map[int64]bool{}
	var destList []int64
	for _, t := range raw.traces {
		if !destIDs[t.dest] {
			destIDs[t.dest] = true
			destList = append(destList, t.dest)
		}
	}
	sortInt64(destList)

	f := filter{}
	selDest, hasSel := parseID(q.Get("dest"))
	if hasSel && destIDs[selDest] {
		f.dest, f.hasDest = selDest, true
	} else {
		selDest = 0
	}
	data := pageData{Source: s.dbPath, Generated: time.Now().Format("2006-01-02 15:04")}
	data.DestOpts = []option{{Value: "", Label: "All destinations", Selected: !f.hasDest}}
	for _, d := range destList {
		data.DestOpts = append(data.DestOpts, option{
			Value: fmt.Sprint(d), Label: raw.fmtIP(d), Selected: f.hasDest && d == f.dest})
	}

	window, _ := parseID(q.Get("window"))
	for _, w := range windowOptions {
		data.WindowOpts = append(data.WindowOpts, option{
			Value: fmt.Sprint(w.secs), Label: w.label, Selected: w.secs == window})
		if w.secs == window && w.secs > 0 && len(raw.traces) > 0 {
			f.t0, f.hasT0 = raw.traces[len(raw.traces)-1].ts-w.secs, true
		}
	}

	unk := q.Get("unk")
	if unk == "" {
		unk = "show"
	}
	for _, m := range unknownModes {
		data.UnkOpts = append(data.UnkOpts, option{Value: m.key, Label: m.label, Selected: m.key == unk})
	}

	A, err := analyze(raw, f, s.geo.lookup(raw.ips))
	if err != nil {
		data.Error = err.Error() // keep the page usable; the filters still show
	} else {
		data.Status = fmt.Sprintf("%d traces · %d destinations · %d route changes",
			A.nTraces, len(A.dests), len(A.events))
		data.Cards = []card{
			{"Traces", fmt.Sprint(A.nTraces)},
			{"Destinations", fmt.Sprint(len(A.dests))},
			{"IPs seen", fmt.Sprint(A.ipCount)},
			{"Distinct routes", fmt.Sprint(A.routesTot)},
			{"Route changes", fmt.Sprint(len(A.events))},
			{"Time span", fmt.Sprintf("%.1f h", float64(A.t1-A.t0)/3600)},
		}
		data.Tabs = s.tabs(A, unk)
	}
	data.CSS = template.CSS(pageCSS)
	data.JS = template.JS(pageJS)

	var buf bytes.Buffer
	if err := pageTmpl.Execute(&buf, data); err != nil {
		log.Print(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(buf.Bytes())
}

func (s *server) tabs(A *analysis, unk string) []tab {
	noGeo := ""
	if len(A.geo) == 0 {
		noGeo = `<p class="muted">No GeoIP data: pass --geo-dir with GeoLite2-City.mmdb / GeoLite2-ASN.mmdb.</p>`
	}
	return []tab{
		{"destinations", "Destinations", template.HTML(A.destTable())},
		{"world-map", "World map", template.HTML(noGeo +
			`<p class="muted">Located IPs (GeoLite2 City, approximate to city level). Map tiles: OpenStreetMap. ` +
			`Red = destination. Lines = hop-to-hop links, thicker = more traces. Private addresses have no location.</p>` +
			`<div class="wrap">` + A.mapSVG(s.zoom) + `</div>`)},
		{"route-timeline", "Route timeline", template.HTML(
			`<p class="muted">Each dot is one traceroute. Colour is the route (non-* hops); a colour change along a row ` +
				`is a route change. Grey = no replies.</p><div class="wrap">` + A.timelineSVG() + `</div>`)},
		{"hop-graph", "Hop graph", template.HTML(
			`<p class="muted">Nodes are IPs, dashed grey nodes are unknown hops. Each column is the average position ` +
				`along the paths; edges are consecutive hops, thicker = more traces. Change "Unknown hops" in the ` +
				`filters above to hide * runs.</p><div class="wrap">` + A.graphSVG(unk) + `</div>`)},
		{"graph-nodes", "Graph nodes", template.HTML(A.graphTable(unk))},
		{"routes", "Routes", template.HTML(A.routesTable())},
		{"changes", "Changes", template.HTML(
			`<p class="muted">A change is a consecutive trace to the same destination whose non-* hops differ.</p>` +
				A.changesTable())},
		{"ips", "IPs", template.HTML(A.ipTable())},
	}
}

func sortInt64(a []int64) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}

func main() {
	dbPath := flag.String("db", defaultDB, "path to traceroute.db (opened read-only)")
	geoDir := flag.String("geo-dir", "", "directory with GeoLite2-City.mmdb / GeoLite2-ASN.mmdb (default: directory of -db)")
	zoom := flag.Int("map-zoom", 2, "OpenStreetMap zoom for the world map (0-4)")
	addr := flag.String("addr", ":8080", "listen address")
	flag.Parse()

	if *zoom < 0 || *zoom > 4 {
		log.Fatal("-map-zoom must be between 0 and 4")
	}
	if *geoDir == "" {
		*geoDir = filepath.Dir(*dbPath)
	}

	// mode=ro: the server never writes to the database.
	db, err := sql.Open("sqlite", fmt.Sprintf("file:%s?mode=ro", *dbPath))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		log.Fatal(err)
	}
	geo := openGeo(*geoDir)
	defer geo.close()

	s := &server{db: db, dbPath: *dbPath, geo: geo, zoom: *zoom}
	http.HandleFunc("/", s.handle)

	log.Printf("serving %s (read-only) on %s", *dbPath, *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}
