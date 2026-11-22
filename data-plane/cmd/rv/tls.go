package main

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

// doctorClient can dial a fixed address while keeping the URL's host name for TLS
// and routing: inside a container, "localhost" is the container itself.
func doctorClient(insecure bool, connect string) *http.Client {
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure}} // #nosec only with -insecure, pilots on self-signed certs
	if connect != "" {
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, connect)
		}
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: transport}
}
