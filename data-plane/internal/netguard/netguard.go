// Package netguard stops pipeline and gateway destinations reaching internal
// addresses. It checks at connect time, after DNS, so that a public name that
// resolves to a private address (DNS rebinding) is refused as well.
package netguard

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"
)

// ErrBlocked means a destination resolved to a non-public address.
var ErrBlocked = errors.New("destination address is not public")

// Public reports whether an address is routable on the public internet.
func Public(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	// 100.64.0.0/10 carrier-grade NAT, and 0.0.0.0/8.
	if v4 := ip.To4(); v4 != nil && ((v4[0] == 100 && v4[1]&0xC0 == 64) || v4[0] == 0) {
		return false
	}
	return true
}

// Client returns an HTTP client that refuses non-public destinations and redirects.
// allowPrivate exists for tests and for customers with private upstreams.
func Client(timeout time.Duration, allowPrivate bool) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		TLSHandshakeTimeout: 5 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if allowPrivate {
				return dialer.DialContext(ctx, network, addr)
			}
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				if Public(ip) {
					return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
				}
			}
			return nil, ErrBlocked
		},
	}
	return &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
