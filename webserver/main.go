// traceviz-web: serve an HTML report generated from traceroute.db.
// Read-only: the database is opened with mode=ro.
package main

import (
	"database/sql"
	"encoding/binary"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var defaultDB = "/home/jon/CLionProjects/traceroute/traceroute.db"

type dest struct {
	Label  string
	Traces int
	Routes int
	Last   string
}

type route struct {
	Dest string
	Hops string
	N    int
}

type report struct {
	Traces, Destinations, IPs, Routes int
	SpanHours                         string
	Dests                             []dest
	TopRoutes                         []route
	Generated                         string
}

// ipString turns the uint32 stored in ips.ip into dotted quad; id 0 / ip 0 is "*".
func ipString(v uint32) string {
	if v == 0 {
		return "*"
	}
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return net.IP(b).String()
}

func build(db *sql.DB) (*report, error) {
	r := &report{Generated: time.Now().Format("2006-01-02 15:04:05")}
	var t0, t1 sql.NullInt64

	if err := db.QueryRow(`SELECT COUNT(*), MIN(ts), MAX(ts) FROM tracerts`).Scan(&r.Traces, &t0, &t1); err != nil {
		return nil, err
	}
	if t1.Valid && t0.Valid {
		r.SpanHours = fmt.Sprintf("%.1f", float64(t1.Int64-t0.Int64)/3600)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM ips`).Scan(&r.IPs); err != nil {
		return nil, err
	}
	if err := db.QueryRow(`SELECT COUNT(DISTINCT path_id) FROM tracerts`).Scan(&r.Routes); err != nil {
		return nil, err
	}

	// Hop id -> display string.
	ips := map[string]string{}
	rows, err := db.Query(`SELECT id, ip FROM ips`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id int64
		var ip uint32
		if err := rows.Scan(&id, &ip); err != nil {
			rows.Close()
			return nil, err
		}
		ips[fmt.Sprint(id)] = ipString(ip)
	}
	rows.Close()

	// Path id -> hop list.
	paths := map[int64]string{}
	rows, err = db.Query(`SELECT path_id, path FROM paths`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var pid int64
		var p string
		if err := rows.Scan(&pid, &p); err != nil {
			rows.Close()
			return nil, err
		}
		var names []string
		for _, h := range strings.Split(p, ",") {
			if h == "" {
				continue
			}
			names = append(names, ips[h])
		}
		paths[pid] = strings.Join(names, " → ")
	}
	rows.Close()

	// Per destination: trace count, distinct routes, last seen.
	rows, err = db.Query(`
		SELECT ip_destination_id, COUNT(*), COUNT(DISTINCT path_id), MAX(ts)
		FROM tracerts GROUP BY ip_destination_id ORDER BY COUNT(*) DESC`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id int64
		var d dest
		var last int64
		if err := rows.Scan(&id, &d.Traces, &d.Routes, &last); err != nil {
			rows.Close()
			return nil, err
		}
		d.Label = ips[fmt.Sprint(id)]
		d.Last = time.Unix(last, 0).Format("2006-01-02 15:04")
		r.Dests = append(r.Dests, d)
	}
	rows.Close()
	r.Destinations = len(r.Dests)

	// Most-used routes.
	rows, err = db.Query(`
		SELECT ip_destination_id, path_id, COUNT(*) AS n
		FROM tracerts GROUP BY ip_destination_id, path_id ORDER BY n DESC LIMIT 20`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var dst, pid int64
		var rt route
		if err := rows.Scan(&dst, &pid, &rt.N); err != nil {
			rows.Close()
			return nil, err
		}
		rt.Dest = ips[fmt.Sprint(dst)]
		rt.Hops = paths[pid]
		r.TopRoutes = append(r.TopRoutes, rt)
	}
	rows.Close()

	return r, nil
}

var page = template.Must(template.New("report").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Traceroute report</title>
<style>
body{font:14px/1.4 system-ui,sans-serif;margin:16px;background:#fafafa;color:#222}
h1{font-size:20px} h2{font-size:16px;margin-top:24px}
.cards{display:flex;flex-wrap:wrap;gap:8px}
.card{background:#fff;border:1px solid #ddd;border-radius:6px;padding:8px 12px}
.card span{display:block;color:#777;font-size:12px}
table{border-collapse:collapse;width:100%;background:#fff;font-size:13px}
th,td{border:1px solid #ddd;padding:4px 8px;text-align:left;vertical-align:top}
th{background:#f0f0f0} .hops{font-family:monospace;word-break:break-word}
.muted{color:#888;font-size:12px}
</style></head><body>
<h1>Traceroute report</h1>
<div class="cards">
 <div class="card"><span>Traces</span><b>{{.Traces}}</b></div>
 <div class="card"><span>Destinations</span><b>{{.Destinations}}</b></div>
 <div class="card"><span>IPs seen</span><b>{{.IPs}}</b></div>
 <div class="card"><span>Distinct routes</span><b>{{.Routes}}</b></div>
 <div class="card"><span>Time span</span><b>{{.SpanHours}} h</b></div>
</div>

<h2>Destinations</h2>
<table><tr><th>Destination</th><th>Traces</th><th>Routes</th><th>Last seen</th></tr>
{{range .Dests}}<tr><td>{{.Label}}</td><td>{{.Traces}}</td><td>{{.Routes}}</td><td>{{.Last}}</td></tr>
{{end}}</table>

<h2>Most used routes</h2>
<table><tr><th>Destination</th><th>Count</th><th>Hops</th></tr>
{{range .TopRoutes}}<tr><td>{{.Dest}}</td><td>{{.N}}</td><td class="hops">{{.Hops}}</td></tr>
{{end}}</table>

<p class="muted">Generated {{.Generated}}</p>
</body></html>`))

func main() {
	dbPath := flag.String("db", defaultDB, "path to traceroute.db (opened read-only)")
	addr := flag.String("addr", ":8080", "listen address")
	flag.Parse()

	// mode=ro: the server never writes to the database.
	db, err := sql.Open("sqlite", fmt.Sprintf("file:%s?mode=ro", *dbPath))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/" {
			http.NotFound(w, req)
			return
		}
		r, err := build(db)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := page.Execute(w, r); err != nil {
			log.Print(err)
		}
	})

	log.Printf("serving %s (read-only) on %s", *dbPath, *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}
