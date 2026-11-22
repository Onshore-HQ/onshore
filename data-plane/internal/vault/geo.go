package vault

import (
	"bytes"
	"encoding/csv"
	"errors"
	"io"
	"net"
	"os"
	"sort"
)

// GeoTable answers country lookups from an offline CSV of start_ip,end_ip,country,
// the layout of the DB-IP Lite download. Nothing leaves the deployment.
type GeoTable struct {
	ranges []geoRange
}

type geoRange struct {
	start, end []byte
	country    string
}

// LoadGeoCSV reads the table.
func LoadGeoCSV(path string) (*GeoTable, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	t := &GeoTable{}
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(rec) < 3 {
			continue
		}
		a, b := net.ParseIP(rec[0]), net.ParseIP(rec[1])
		if a == nil || b == nil {
			continue
		}
		t.ranges = append(t.ranges, geoRange{a.To16(), b.To16(), rec[2]})
	}
	sort.Slice(t.ranges, func(i, j int) bool { return bytes.Compare(t.ranges[i].start, t.ranges[j].start) < 0 })
	return t, nil
}

// Country returns the ISO code for an address, or "" if unknown.
func (t *GeoTable) Country(ip string) string {
	p := net.ParseIP(ip)
	if p == nil {
		return ""
	}
	k := p.To16()
	i := sort.Search(len(t.ranges), func(i int) bool { return bytes.Compare(t.ranges[i].start, k) > 0 }) - 1
	if i >= 0 && bytes.Compare(k, t.ranges[i].end) <= 0 {
		return t.ranges[i].country
	}
	return ""
}
