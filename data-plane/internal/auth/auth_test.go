package auth

import (
	"net/http"
	"testing"
)

func TestClientIP(t *testing.T) {
	trusted, _ := ParseCIDRs("10.0.0.0/8")
	a := &Authenticator{Trusted: trusted}
	cases := []struct{ remote, xff, want string }{
		{"203.0.113.9:1", "1.2.3.4", "203.0.113.9"},                       // untrusted peer cannot spoof
		{"10.0.0.2:1", "198.51.100.7", "198.51.100.7"},                    // via the edge
		{"10.0.0.2:1", "1.2.3.4, 198.51.100.7", "198.51.100.7"},           // forged left entry ignored
		{"10.0.0.2:1", "1.2.3.4, 198.51.100.7, 10.0.0.3", "198.51.100.7"}, // past trusted hops
		{"10.0.0.2:1", "", "10.0.0.2"},
	}
	for _, c := range cases {
		r := &http.Request{RemoteAddr: c.remote, Header: http.Header{}}
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := a.ClientIP(r); got != c.want {
			t.Errorf("remote=%s xff=%q: got %s want %s", c.remote, c.xff, got, c.want)
		}
	}
}

func TestIPAllowed(t *testing.T) {
	if !ipAllowed("1.2.3.4", nil) || !ipAllowed("10.1.1.1", []string{"10.0.0.0/8"}) || !ipAllowed("1.2.3.4", []string{"1.2.3.4"}) {
		t.Fatal("should allow")
	}
	if ipAllowed("1.2.3.4", []string{"10.0.0.0/8"}) || ipAllowed("junk", []string{"10.0.0.0/8"}) {
		t.Fatal("should refuse")
	}
}
