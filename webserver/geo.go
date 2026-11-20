package main

// GeoIP/ASN lookups with the GeoLite2 City and ASN databases, like geo_lookup() in traceviz.py.
// Optional: without the .mmdb files the location and network sections are left empty.

import (
	"log"
	"net"
	"os"
	"path/filepath"

	"github.com/oschwald/maxminddb-golang"
)

type geoRec struct {
	Private bool
	CGNAT   bool
	Country string
	City    string
	Lat     *float64
	Lon     *float64
	ASN     uint
	Org     string
}

type cityDB struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Location struct {
		Latitude  *float64 `maxminddb:"latitude"`
		Longitude *float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
}

type asnDB struct {
	Number uint   `maxminddb:"autonomous_system_number"`
	Org    string `maxminddb:"autonomous_system_organization"`
}

type geoReaders struct {
	city *maxminddb.Reader
	asn  *maxminddb.Reader
}

// openGeo opens GeoLite2-City.mmdb and GeoLite2-ASN.mmdb from dir. It returns nil when neither exists.
func openGeo(dir string) *geoReaders {
	g := &geoReaders{}
	var err error
	if p := filepath.Join(dir, "GeoLite2-City.mmdb"); fileExists(p) {
		if g.city, err = maxminddb.Open(p); err != nil {
			log.Fatal(err)
		}
	}
	if p := filepath.Join(dir, "GeoLite2-ASN.mmdb"); fileExists(p) {
		if g.asn, err = maxminddb.Open(p); err != nil {
			log.Fatal(err)
		}
	}
	if g.city == nil && g.asn == nil {
		log.Printf("no GeoLite2 .mmdb files in %s, skipping GeoIP/ASN", dir)
		return nil
	}
	return g
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func (g *geoReaders) close() {
	if g == nil {
		return
	}
	if g.city != nil {
		g.city.Close()
	}
	if g.asn != nil {
		g.asn.Close()
	}
}

var cgnatNet = mustCIDR("100.64.0.0/10")

// Ranges Python's ipaddress.is_private treats as private (CGNAT is handled separately).
var privateNets = []*net.IPNet{
	mustCIDR("0.0.0.0/8"), mustCIDR("10.0.0.0/8"), mustCIDR("127.0.0.0/8"), mustCIDR("169.254.0.0/16"),
	mustCIDR("172.16.0.0/12"), mustCIDR("192.0.0.0/24"), mustCIDR("192.0.2.0/24"), mustCIDR("192.168.0.0/16"),
	mustCIDR("198.18.0.0/15"), mustCIDR("198.51.100.0/24"), mustCIDR("203.0.113.0/24"), mustCIDR("240.0.0.0/4"),
	mustCIDR("255.255.255.255/32"),
}

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// lookup returns the geo record per IP id; the * hop (ip 0) is skipped.
func (g *geoReaders) lookup(ips map[int64]uint32) map[int64]*geoRec {
	out := map[int64]*geoRec{}
	if g == nil {
		return out
	}
	for id, v := range ips {
		if v == noReplyIP {
			continue
		}
		ip := net.ParseIP(fmtIP(v))
		rec := &geoRec{}
		rec.CGNAT = cgnatNet.Contains(ip)
		rec.Private = rec.CGNAT || ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || inAny(ip, privateNets)
		if !rec.Private {
			if g.city != nil {
				var c cityDB
				if err := g.city.Lookup(ip, &c); err == nil {
					rec.Country = c.Country.ISOCode
					rec.City = c.City.Names["en"]
					rec.Lat, rec.Lon = c.Location.Latitude, c.Location.Longitude
				}
			}
			if g.asn != nil {
				var a asnDB
				if err := g.asn.Lookup(ip, &a); err == nil {
					rec.ASN, rec.Org = a.Number, a.Org
				}
			}
		}
		out[id] = rec
	}
	return out
}

func inAny(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
