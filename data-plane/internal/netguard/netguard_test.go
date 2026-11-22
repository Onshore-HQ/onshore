package netguard

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPublic(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "172.30.0.5", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fe80::1", "fc00::1"} {
		if Public(net.ParseIP(ip)) {
			t.Errorf("%s must not be public", ip)
		}
	}
	for _, ip := range []string{"8.8.8.8", "102.89.1.1", "2606:4700::1111"} {
		if !Public(net.ParseIP(ip)) {
			t.Errorf("%s must be public", ip)
		}
	}
}

func TestClientRefusesLocalServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	_, err := Client(time.Second, false).Get(srv.URL)
	if err == nil || !strings.Contains(err.Error(), "not public") {
		t.Fatalf("expected a refusal, got %v", err)
	}
	if _, err := Client(time.Second, true).Get(srv.URL); err != nil {
		t.Fatalf("allowPrivate: %v", err)
	}
}
