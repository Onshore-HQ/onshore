package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const importBatch = 450

type importer struct {
	base, vault, sa, kid string
	key                  ed25519.PrivateKey
	http                 *http.Client
	token                string
	expiry               time.Time
}

func (im *importer) bearer() (string, error) {
	if im.token != "" && time.Now().Before(im.expiry.Add(-time.Minute)) {
		return im.token, nil
	}
	enc := base64.RawURLEncoding.EncodeToString
	head, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": im.kid})
	now := time.Now().Unix()
	body, _ := json.Marshal(map[string]any{"iss": im.sa, "sub": im.sa, "aud": "onshore", "iat": now, "exp": now + 60, "jti": secret(16)})
	s := enc(head) + "." + enc(body)
	a := s + "." + enc(ed25519.Sign(im.key, []byte(s)))
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := im.post("/v1/auth/token", "", map[string]string{"assertion": a}, &out); err != nil {
		return "", fmt.Errorf("the service account could not sign in: %w", err)
	}
	im.token, im.expiry = out.AccessToken, time.Now().Add(time.Duration(out.ExpiresIn)*time.Second)
	return im.token, nil
}

func (im *importer) post(path, token string, in, out any) error {
	b, _ := json.Marshal(in)
	var last error
	for attempt := 0; attempt < 5; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 2 * time.Second)
		}
		req, _ := http.NewRequest("POST", im.base+path, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		res, err := im.http.Do(req)
		if err != nil {
			last = errors.New("could not reach Onshore")
			continue
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode >= 500 || res.StatusCode == 429 {
			last = fmt.Errorf("Onshore answered %d", res.StatusCode)
			continue
		}
		if res.StatusCode >= 400 {
			var e struct {
				Error struct{ Code, Message string } `json:"error"`
			}
			_ = json.Unmarshal(body, &e)
			return fmt.Errorf("%s: %s", e.Error.Code, e.Error.Message)
		}
		return json.Unmarshal(body, out)
	}
	return last
}

type importResult struct {
	Results []struct {
		Index    int   `json:"index"`
		Existing *bool `json:"existing"`
		Token    string `json:"token"`
		Error    *struct {
			Code string `json:"code"`
		} `json:"error"`
	} `json:"results"`
}

// cmdImport loads a CSV into a vault in small batches through the normal API, so that access rules
// and the audit log apply. It writes the same CSV with tokens in place of the sensitive columns, and
// can be stopped and run again: it carries on from a progress file beside its output.
func cmdImport(args []string) error {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	base := fs.String("url", "", "Onshore's address, such as https://vault.yourbank.ng")
	vaultID := fs.String("vault", "", "vault ID")
	sa := fs.String("sa", "", "service account ID")
	kid := fs.String("key-id", "", "service account key ID")
	keyFile := fs.String("key-file", "", "file holding the key's private seed, from rv sa-keygen")
	file := fs.String("file", "", "the CSV to load")
	mapping := fs.String("map", "", "columns to protect, as column=field,column=field")
	ref := fs.String("ref", "", "column holding your customer reference (optional)")
	out := fs.String("out", "", "where to write the CSV with tokens (default: <file>.tokens.csv)")
	errsOut := fs.String("errors", "", "where to write the rows that failed (default: <file>.errors.csv)")
	check := fs.Bool("check", false, "check every value and store nothing")
	insecure := fs.Bool("insecure", false, "don't check the TLS certificate; for a pilot with an internal CA")
	_ = fs.Parse(args)
	if *base == "" || *vaultID == "" || *sa == "" || *kid == "" || *keyFile == "" || *file == "" || *mapping == "" {
		fs.Usage()
		return errors.New("-url, -vault, -sa, -key-id, -key-file, -file and -map are required")
	}
	seedText, err := os.ReadFile(*keyFile)
	if err != nil {
		return errors.New("could not read the key file")
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(seedText)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return errors.New("the key file should hold the base64 private seed from rv sa-keygen")
	}
	cols := map[string]string{}
	for _, pair := range strings.Split(*mapping, ",") {
		c, f, ok := strings.Cut(pair, "=")
		if !ok || c == "" || f == "" {
			return fmt.Errorf("can't read %q: use column=field", pair)
		}
		cols[c] = f
	}
	if *out == "" {
		*out = *file + ".tokens.csv"
	}
	if *errsOut == "" {
		*errsOut = *file + ".errors.csv"
	}
	progress := *out + ".progress"

	in, err := os.Open(*file)
	if err != nil {
		return errors.New("could not open the file")
	}
	defer in.Close()
	r := csv.NewReader(in)
	r.FieldsPerRecord = -1
	header, err := r.Read()
	if err != nil {
		return errors.New("could not read the first line of the file")
	}
	pos := map[string]int{}
	for i, h := range header {
		pos[strings.TrimPrefix(h, "\xef\xbb\xbf")] = i
	}
	for c := range cols {
		if _, ok := pos[c]; !ok {
			return fmt.Errorf("the file has no column called %q", c)
		}
	}
	refAt := -1
	if *ref != "" {
		at, ok := pos[*ref]
		if !ok {
			return fmt.Errorf("the file has no column called %q", *ref)
		}
		refAt = at
	}

	skip := 0
	if !*check {
		if b, err := os.ReadFile(progress); err == nil {
			skip, _ = strconv.Atoi(strings.TrimSpace(string(b)))
		}
	}
	flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	var tokensCSV, errsCSV *csv.Writer
	var tf, ef *os.File
	if !*check {
		if tf, err = os.OpenFile(*out, flags, 0o600); err != nil {
			return errors.New("could not write the output file")
		}
		defer tf.Close()
		tokensCSV = csv.NewWriter(tf)
		if skip == 0 {
			if err := tf.Truncate(0); err != nil {
				return err
			}
			_ = tokensCSV.Write(header)
		}
	}
	if ef, err = os.OpenFile(*errsOut, flags, 0o600); err != nil {
		return errors.New("could not write the errors file")
	}
	defer ef.Close()
	errsCSV = csv.NewWriter(ef)
	if skip == 0 {
		_ = ef.Truncate(0)
		_ = errsCSV.Write([]string{"row", "column", "problem"})
	}

	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: *insecure}
	im := &importer{base: strings.TrimRight(*base, "/"), vault: *vaultID, sa: *sa, kid: *kid, key: ed25519.NewKeyFromSeed(seed), http: &http.Client{Timeout: 2 * time.Minute, Transport: tr}}

	type slot struct {
		row    int
		column string
		at     int
	}
	var rows [][]string
	var failedRows = map[int]bool{}
	items := []map[string]string{}
	slots := []slot{}
	rowNo, done, failed, created, existing := 0, 0, 0, 0, 0
	flush := func() error {
		if len(rows) == 0 {
			return nil
		}
		if len(items) > 0 {
			token, err := im.bearer()
			if err != nil {
				return err
			}
			var res importResult
			if err := im.post("/v1/vaults/"+im.vault+"/tokenize", token, map[string]any{"items": items, "continue_on_error": true, "dry_run": *check}, &res); err != nil {
				return err
			}
			for _, x := range res.Results {
				s := slots[x.Index]
				if x.Error != nil {
					_ = errsCSV.Write([]string{strconv.Itoa(s.row), s.column, x.Error.Code})
					failedRows[s.row] = true
					// A value that failed must not stay in the output.
					rows[s.row-(rowNo-len(rows))-1][s.at] = ""
					continue
				}
				if !*check {
					rows[s.row-(rowNo-len(rows))-1][s.at] = x.Token
					if x.Existing != nil && *x.Existing {
						existing++
					} else {
						created++
					}
				}
			}
		}
		for i, row := range rows {
			n := rowNo - len(rows) + i + 1
			if failedRows[n] {
				failed++
			} else {
				done++
			}
			if tokensCSV != nil {
				_ = tokensCSV.Write(row)
			}
		}
		if tokensCSV != nil {
			tokensCSV.Flush()
			if err := tokensCSV.Error(); err != nil {
				return errors.New("could not write the output file")
			}
			// Written after the tokens, so a crash can only repeat work, never lose it.
			if err := os.WriteFile(progress, []byte(strconv.Itoa(rowNo)), 0o600); err != nil {
				return err
			}
		}
		errsCSV.Flush()
		rows, items, slots, failedRows = rows[:0], items[:0], slots[:0], map[int]bool{}
		fmt.Fprintf(os.Stderr, "\r%d rows: %d fine, %d with problems", rowNo, done, failed)
		return nil
	}
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("line %d of the file can't be read as CSV", rowNo+2)
		}
		rowNo++
		if rowNo <= skip {
			continue
		}
		subject := ""
		if refAt >= 0 && refAt < len(rec) {
			subject = rec[refAt]
		}
		if len(items)+len(cols) > importBatch {
			rowNo--
			if err := flush(); err != nil {
				return err
			}
			rowNo++
		}
		rows = append(rows, rec)
		for c, f := range cols {
			at := pos[c]
			if at >= len(rec) || rec[at] == "" {
				continue
			}
			items = append(items, map[string]string{"field": f, "value": rec[at], "subject_ref": subject})
			slots = append(slots, slot{rowNo, c, at})
		}
	}
	if err := flush(); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr)
	if *check {
		fmt.Printf("Checked %d rows: %d fine, %d with problems. Nothing was stored.\nProblems: %s\n", rowNo, done, failed, *errsOut)
		return nil
	}
	_ = os.Remove(progress)
	fmt.Printf("Done. %d rows: %d fine, %d with problems. %d new values, %d already held.\nTokens: %s\nProblems: %s\nReplace the values in your database with these tokens, then delete the original file.\n", rowNo, done, failed, created, existing, *out, *errsOut)
	return nil
}
