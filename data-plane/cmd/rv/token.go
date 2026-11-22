package main

import (
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// cmdToken signs a service-account assertion and prints a 15-minute bearer token,
// for trying the API by hand (curl, the API reference). Only the token is printed.
func cmdToken(args []string) error {
	fs := flag.NewFlagSet("token", flag.ExitOnError)
	base := fs.String("url", os.Getenv("ONSHORE_URL"), "Onshore's address, such as https://vault.yourhost.example (or ONSHORE_URL)")
	sa := fs.String("sa", os.Getenv("ONSHORE_SA_ID"), "service account ID (or ONSHORE_SA_ID)")
	kid := fs.String("key-id", os.Getenv("ONSHORE_KEY_ID"), "service account key ID (or ONSHORE_KEY_ID)")
	keyFile := fs.String("key-file", "", "file holding the key's private seed, from rv sa-keygen")
	insecure := fs.Bool("insecure", false, "don't check the TLS certificate; for a pilot with an internal CA")
	_ = fs.Parse(args)
	if *base == "" || *sa == "" || *kid == "" || *keyFile == "" {
		fs.Usage()
		return errors.New("-url, -sa, -key-id and -key-file are required")
	}
	seedText, err := os.ReadFile(*keyFile)
	if err != nil {
		return errors.New("could not read the key file")
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(seedText)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return errors.New("the key file should hold the base64 private seed from rv sa-keygen")
	}
	client := &http.Client{Timeout: 15 * time.Second}
	if *insecure {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // opt-in for pilots
	}
	im := &importer{base: strings.TrimRight(*base, "/"), sa: *sa, kid: *kid, key: ed25519.NewKeyFromSeed(seed), http: client}
	tok, err := im.bearer()
	if err != nil {
		return err
	}
	fmt.Println(tok)
	return nil
}
