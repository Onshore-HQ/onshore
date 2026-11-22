package gateway

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"onshore/data-plane/internal/detect"
	"onshore/data-plane/internal/logproc"
	"onshore/data-plane/internal/mask"
	"onshore/data-plane/internal/vault"
)

// Every format here fails closed. A body that cannot be fully read does not pass, since
// whatever could not be read could not be checked. Forms, multipart and headers are also
// written back in one canonical form, so that the upstream cannot parse them differently
// from the way they were checked.
var (
	ErrUnreadable  = errors.New("this body cannot be read under this route's rules")
	ErrEncoded     = errors.New("a compressed body cannot be checked")
	ErrFileRefused = errors.New("this route refuses files")
	ErrFileService = errors.New("the file service cannot process this")
)

// HeaderRule names one header, and when tokenizing into a chosen column, its field.
type HeaderRule struct {
	Header string `json:"header"`
	Field  string `json:"field,omitempty"`
}

// File policies, for a binary body or part.
const (
	FileRefuse = "refuse" // the default: nothing unread passes
	FileRedact = "redact" // through the file redactor, PDF and images only
	FilePass   = "pass"   // sent unread, by an admin's explicit choice, and counted
)

const (
	maxFormPairs  = 10_000
	maxParts      = 200
	maxXMLDepth   = 256
	maxXMLLeaves  = 100_000
	maxHeaderRule = 64
)

// readableCharsets all write ASCII digits and letters as themselves.
var readableCharsets = map[string]bool{"utf-8": true, "utf8": true, "us-ascii": true, "ascii": true, "iso-8859-1": true, "latin1": true, "windows-1252": true}

// Body transforms a request or response body according to its declared type.
func (t *Transformer) Body(ctx context.Context, r *ProxyRoute, contentType, contentEncoding string, body []byte, redact, unredact []PathRule, caller string, dlp bool) ([]byte, string, logproc.Counts, error) {
	if len(redact)+len(unredact) == 0 && !dlp {
		return body, contentType, logproc.Counts{}, nil
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return body, contentType, logproc.Counts{}, nil
	}
	if ce := strings.ToLower(strings.TrimSpace(contentEncoding)); ce != "" && ce != "identity" {
		return nil, "", nil, ErrEncoded
	}
	json := func() ([]byte, string, logproc.Counts, error) {
		out, c, err := t.apply(ctx, r, body, redact, unredact, caller, dlp)
		return out, contentType, c, err
	}
	if strings.TrimSpace(contentType) == "" {
		return json()
	}
	mt, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, "", nil, ErrUnreadable
	}
	// In UTF-7 or UTF-16 a digit is not the byte it looks like, so a value would pass unseen.
	if cs := strings.ToLower(params["charset"]); cs != "" && !readableCharsets[cs] {
		return nil, "", nil, ErrUnreadable
	}
	switch {
	case mt == "application/json" || strings.HasSuffix(mt, "+json"):
		return json()
	case mt == "application/x-www-form-urlencoded":
		out, c, err := t.form(ctx, r, body, redact, unredact, caller, dlp)
		return out, contentType, c, err
	case mt == "multipart/form-data":
		out, c, err := t.multipartBody(ctx, r, body, params["boundary"], redact, unredact, caller, dlp)
		return out, contentType, c, err
	case strings.HasPrefix(mt, "multipart/"):
		return nil, "", nil, ErrUnreadable
	case mt == "text/xml" || mt == "application/xml" || strings.HasSuffix(mt, "+xml"):
		out, c, err := t.xmlBody(ctx, r, body, redact, unredact, caller, dlp)
		return out, contentType, c, err
	case strings.HasPrefix(mt, "text/"):
		// JSON sent with the wrong label is still JSON: reading it as such checks more.
		if trimmed := bytes.TrimSpace(body); trimmed[0] == '{' || trimmed[0] == '[' {
			if _, err := decodeJSON(body); err == nil {
				return json()
			}
		}
		out, c, err := t.textBody(ctx, r, body, redact, unredact, caller, dlp)
		return out, contentType, c, err
	}
	return t.fileBody(ctx, r, contentType, body, redact, unredact, caller, dlp)
}

// leaves applies redact rules, unredact rules and detection to values however they were
// parsed. Paths compare exactly. Set must store the value it is given.
func (t *Transformer) leaves(ctx context.Context, r *ProxyRoute, ls []logproc.Leaf, redact, unredact []PathRule, caller string, dlp bool) (logproc.Counts, error) {
	counts := logproc.Counts{}
	processOnly := r.Mode == "process_only"
	set := func(i int, v string) { ls[i].Value = v; ls[i].Set(v) }

	var at []int
	var items []logproc.Item
	for _, rule := range redact {
		for i := range ls {
			if ls[i].Path == rule.Path && ls[i].Value != "" {
				at = append(at, i)
				items = append(items, logproc.Item{Field: rule.Field, Entity: "free_text", Value: ls[i].Value})
			}
		}
	}
	tokens := make([]string, len(items))
	if processOnly {
		for i := range items {
			tokens[i] = vault.NewToken("free_text", "opaque")
		}
	} else if len(items) > 0 {
		var err error
		if tokens, err = t.Tokenize(ctx, r, items); err != nil {
			return nil, err
		}
	}
	for n, i := range at {
		tok := tokens[n]
		if tok == "" {
			tok = mask.Value("", "full", items[n].Value)
		}
		set(i, tok)
		counts[[2]string{"path_rule", "tokenized"}]++
	}

	if len(unredact) > 0 && t.Reveal != nil && caller != "" && !processOnly {
		var uat []int
		var want []string
		for _, rule := range unredact {
			for i := range ls {
				if ls[i].Path == rule.Path && ls[i].Value != "" {
					uat = append(uat, i)
					want = append(want, ls[i].Value)
				}
			}
		}
		if len(want) > 0 {
			vals, err := t.Reveal(ctx, r, caller, want)
			if err != nil {
				return nil, err
			}
			for n, i := range uat {
				v, ok := vals[want[n]]
				if !ok {
					continue
				}
				// A restored value must not be able to add a header of its own.
				if strings.HasPrefix(ls[i].Path, "header:") && strings.ContainsAny(v, "\r\n\x00") {
					continue
				}
				set(i, v)
			}
		}
	}
	if dlp {
		c, _, err := t.dlpLeaves(ctx, r, ls)
		if err != nil {
			return nil, err
		}
		for k, n := range c {
			counts[k] += n
		}
	}
	return counts, nil
}

var formIndex = regexp.MustCompile(`\[(\d*)\]`)
var formKey = regexp.MustCompile(`\[([^\[\]]+)\]`)

// formPath writes a field name as a path: customer[bvn] is $.customer.bvn, and both
// items[0][bvn] and items[][bvn] are $.items[*].bvn.
func formPath(name string) string {
	p := formIndex.ReplaceAllString(name, "[*]")
	p = strings.ReplaceAll(p, "[*]", "\x00")
	p = formKey.ReplaceAllString(p, ".$1")
	p = strings.ReplaceAll(p, "\x00", "[*]")
	return "$." + p
}

func (t *Transformer) form(ctx context.Context, r *ProxyRoute, body []byte, redact, unredact []PathRule, caller string, dlp bool) ([]byte, logproc.Counts, error) {
	if !utf8.Valid(body) {
		return nil, nil, ErrUnreadable
	}
	raw := strings.Split(strings.TrimSpace(string(body)), "&")
	if len(raw) > maxFormPairs {
		return nil, nil, ErrUnreadable
	}
	type pair struct{ k, v string }
	pairs := make([]pair, 0, len(raw))
	var ls []logproc.Leaf
	for _, kv := range raw {
		if kv == "" {
			continue
		}
		k, v, _ := strings.Cut(kv, "=")
		key, err1 := url.QueryUnescape(k)
		val, err2 := url.QueryUnescape(v)
		if err1 != nil || err2 != nil || !utf8.ValidString(key) || !utf8.ValidString(val) || strings.IndexByte(key+val, 0) >= 0 {
			return nil, nil, ErrUnreadable
		}
		pairs = append(pairs, pair{key, val})
		i := len(pairs) - 1
		ls = append(ls, logproc.Leaf{Value: val, Hint: key, Path: formPath(key), Set: func(s string) { pairs[i].v = s }})
	}
	counts, err := t.leaves(ctx, r, ls, redact, unredact, caller, dlp)
	if err != nil {
		return nil, nil, err
	}
	var b strings.Builder
	for i, p := range pairs {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(url.QueryEscape(p.k) + "=" + url.QueryEscape(p.v))
	}
	return []byte(b.String()), counts, nil
}

// textBody reads plain text. A field rule has nothing to name in it, so it does not pass.
func (t *Transformer) textBody(ctx context.Context, r *ProxyRoute, body []byte, redact, unredact []PathRule, caller string, dlp bool) ([]byte, logproc.Counts, error) {
	if len(redact)+len(unredact) > 0 {
		return nil, nil, ErrNotJSON
	}
	// NUL is valid UTF-8, and is how UTF-16 text looks when read as bytes: 2\x002\x003\x00.
	if !utf8.Valid(body) || bytes.IndexByte(body, 0) >= 0 {
		return nil, nil, ErrUnreadable
	}
	out := string(body)
	counts, err := t.leaves(ctx, r, []logproc.Leaf{{Value: out, Path: "$", Set: func(s string) { out = s }}}, nil, nil, caller, dlp)
	return []byte(out), counts, err
}

// fileKind is decided by what the bytes are, not what the request says they are.
func fileKind(b []byte) string {
	switch {
	case bytes.HasPrefix(b, []byte("%PDF-")):
		return "pdf"
	case bytes.HasPrefix(b, []byte{0x89, 'P', 'N', 'G'}), bytes.HasPrefix(b, []byte{0xFF, 0xD8, 0xFF}), bytes.HasPrefix(b, []byte("GIF8")), bytes.HasPrefix(b, []byte("II*\x00")), bytes.HasPrefix(b, []byte("MM\x00*")):
		return "image"
	}
	if utf8.Valid(b) && !bytes.ContainsRune(b, 0) {
		return "text"
	}
	return "binary"
}

// binary applies the route's file policy to bytes that are not text.
func (t *Transformer) binary(ctx context.Context, r *ProxyRoute, body []byte, kind string, counts logproc.Counts) ([]byte, string, error) {
	switch r.FilePolicy {
	case FilePass:
		counts[[2]string{"file", "uninspected"}]++
		return body, "", nil
	case FileRedact:
		if (kind != "pdf" && kind != "image") || t.RedactFile == nil {
			return nil, "", ErrFileRefused
		}
		out, ct, found, low, err := t.RedactFile(ctx, r, body)
		if err != nil {
			return nil, "", err
		}
		// A file nobody could read with confidence might still hold what it seemed not to.
		if low {
			return nil, "", ErrFileRefused
		}
		for entity, n := range found {
			counts[[2]string{entity, "redacted"}] += int64(n)
		}
		counts[[2]string{"file", "redacted"}]++
		return out, ct, nil
	}
	return nil, "", ErrFileRefused
}

func (t *Transformer) fileBody(ctx context.Context, r *ProxyRoute, contentType string, body []byte, redact, unredact []PathRule, caller string, dlp bool) ([]byte, string, logproc.Counts, error) {
	kind := fileKind(body)
	if kind == "text" {
		out, c, err := t.textBody(ctx, r, body, redact, unredact, caller, dlp)
		return out, contentType, c, err
	}
	if len(redact)+len(unredact) > 0 {
		return nil, "", nil, ErrUnreadable
	}
	counts := logproc.Counts{}
	out, ct, err := t.binary(ctx, r, body, kind, counts)
	if err != nil {
		return nil, "", nil, err
	}
	if ct == "" {
		ct = contentType
	}
	return out, ct, counts, nil
}

func (t *Transformer) multipartBody(ctx context.Context, r *ProxyRoute, body []byte, boundary string, redact, unredact []PathRule, caller string, dlp bool) ([]byte, logproc.Counts, error) {
	if boundary == "" {
		return nil, nil, ErrUnreadable
	}
	type part struct {
		name, filename, contentType string
		data                        []byte
		text                        bool
	}
	var parts []*part
	var ls []logproc.Leaf
	rd := multipart.NewReader(bytes.NewReader(body), boundary)
	counts := logproc.Counts{}
	named := map[string]bool{}
	for _, rule := range append(append([]PathRule{}, redact...), unredact...) {
		named[rule.Path] = true
	}
	for {
		p, err := rd.NextRawPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || len(parts) >= maxParts {
			return nil, nil, ErrUnreadable
		}
		// Base64 or quoted-printable would carry a value past the checks unread.
		if te := strings.ToLower(p.Header.Get("Content-Transfer-Encoding")); te != "" && te != "7bit" && te != "8bit" && te != "binary" {
			return nil, nil, ErrUnreadable
		}
		disposition, dp, err := mime.ParseMediaType(p.Header.Get("Content-Disposition"))
		if err != nil || disposition != "form-data" || dp["name"] == "" {
			return nil, nil, ErrUnreadable
		}
		ct := p.Header.Get("Content-Type")
		if strings.HasPrefix(strings.ToLower(ct), "multipart/") {
			return nil, nil, ErrUnreadable
		}
		data, err := io.ReadAll(p)
		if err != nil {
			return nil, nil, ErrUnreadable
		}
		cur := &part{name: dp["name"], filename: dp["filename"], contentType: ct, data: data}
		parts = append(parts, cur)
		path := formPath(cur.name)
		if kind := fileKind(data); kind == "text" {
			cur.text = true
			ls = append(ls, logproc.Leaf{Value: string(data), Hint: cur.name, Path: path, Set: func(s string) { cur.data = []byte(s) }})
		} else {
			// A rule naming a value that cannot be read cannot be honoured.
			if named[path] {
				return nil, nil, ErrUnreadable
			}
			out, newType, err := t.binary(ctx, r, data, kind, counts)
			if err != nil {
				return nil, nil, err
			}
			cur.data = out
			if newType != "" {
				cur.contentType = newType
			}
		}
		if cur.filename != "" {
			ls = append(ls, logproc.Leaf{Value: cur.filename, Hint: "filename", Path: path + ".filename", Set: func(s string) { cur.filename = s }})
		}
	}
	c, err := t.leaves(ctx, r, ls, redact, unredact, caller, dlp)
	if err != nil {
		return nil, nil, err
	}
	for k, n := range c {
		counts[k] += n
	}
	var out bytes.Buffer
	w := multipart.NewWriter(&out)
	if err := w.SetBoundary(boundary); err != nil {
		return nil, nil, ErrUnreadable
	}
	for _, p := range parts {
		// Quoted, as browsers write it: older servers do not all read the bare form.
		disposition := `form-data; name="` + quoteParam(p.name) + `"`
		if p.filename != "" {
			disposition += `; filename="` + quoteParam(p.filename) + `"`
		}
		h := textproto.MIMEHeader{"Content-Disposition": {disposition}}
		if p.contentType != "" {
			h.Set("Content-Type", p.contentType)
		}
		pw, err := w.CreatePart(h)
		if err != nil {
			return nil, nil, ErrUnreadable
		}
		if _, err := pw.Write(p.data); err != nil {
			return nil, nil, err
		}
	}
	if err := w.Close(); err != nil {
		return nil, nil, err
	}
	return out.Bytes(), counts, nil
}

var paramQuoter = strings.NewReplacer("\\", "\\\\", `"`, "\\\"", "\r", "", "\n", "")

func quoteParam(s string) string { return paramQuoter.Replace(s) }

var xmlAttr = regexp.MustCompile(`([^\s=<>"'/]+)\s*=\s*(?:"([^"]*)"|'([^']*)')`)

type xmlEdit struct {
	start, end int
	text       string
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	xml.EscapeText(&b, []byte(s))
	return b.String()
}

// xmlBody edits text and attribute values where they stand, so that namespaces, prefixes,
// order and whitespace reach the upstream as sent. A SOAP envelope survives unchanged
// apart from the values. A path uses local names: $.Envelope.Body.Customer.BVN, and
// $.Customer.@id for an attribute.
func (t *Transformer) xmlBody(ctx context.Context, r *ProxyRoute, body []byte, redact, unredact []PathRule, caller string, dlp bool) ([]byte, logproc.Counts, error) {
	if !utf8.Valid(body) {
		return nil, nil, ErrUnreadable
	}
	dec := xml.NewDecoder(bytes.NewReader(body))
	dec.Strict = true
	var stack []string
	var ls []logproc.Leaf
	var edits []*xmlEdit
	var procs []string
	add := func(value, path, hint string, start, end int, wrap func(string) string) {
		e := &xmlEdit{start: start, end: end}
		original := value
		ls = append(ls, logproc.Leaf{Value: value, Hint: hint, Path: path, Set: func(s string) {
			if s != original {
				e.text = wrap(s)
				edits = append(edits, e)
			}
		}})
	}
	sawRoot := false
	for {
		start := int(dec.InputOffset())
		tok, err := dec.RawToken()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, ErrUnreadable
		}
		end := int(dec.InputOffset())
		if len(ls) > maxXMLLeaves {
			return nil, nil, ErrUnreadable
		}
		switch v := tok.(type) {
		case xml.StartElement:
			if len(stack) >= maxXMLDepth {
				return nil, nil, ErrUnreadable
			}
			sawRoot = true
			stack = append(stack, v.Name.Local)
			path := "$." + strings.Join(stack, ".")
			raw := body[start:end]
			// Skips the element's own name, then reads each attribute with its position.
			nameEnd := bytes.IndexAny(raw, " \t\r\n/>")
			if nameEnd < 0 {
				return nil, nil, ErrUnreadable
			}
			for _, m := range xmlAttr.FindAllSubmatchIndex(raw[nameEnd:], -1) {
				name := string(raw[nameEnd+m[2] : nameEnd+m[3]])
				vs, ve := m[4], m[5]
				if vs < 0 {
					vs, ve = m[6], m[7]
				}
				if strings.HasPrefix(name, "xmlns") {
					continue
				}
				var value string
				if err := unescapeXML(raw[nameEnd+vs:nameEnd+ve], &value); err != nil {
					return nil, nil, ErrUnreadable
				}
				local := name
				if i := strings.IndexByte(local, ':'); i >= 0 {
					local = local[i+1:]
				}
				add(value, path+".@"+local, local, start+nameEnd+vs, start+nameEnd+ve, xmlEscape)
			}
		case xml.EndElement:
			if len(stack) == 0 || stack[len(stack)-1] != v.Name.Local {
				return nil, nil, ErrUnreadable
			}
			stack = stack[:len(stack)-1]
		case xml.CharData:
			text := string(v)
			if strings.TrimSpace(text) == "" {
				continue
			}
			if len(stack) == 0 {
				return nil, nil, ErrUnreadable
			}
			add(text, "$."+strings.Join(stack, "."), stack[len(stack)-1], start, end, xmlEscape)
		case xml.Comment:
			add(string(v), "xml:comment", "", start, end, func(s string) string { return "<!--" + strings.ReplaceAll(s, "--", "__") + "-->" })
		case xml.Directive:
			// A DOCTYPE can define entities the upstream would expand and this cannot see.
			return nil, nil, ErrUnreadable
		case xml.ProcInst:
			procs = append(procs, string(v.Inst))
		}
	}
	if len(stack) != 0 || !sawRoot {
		return nil, nil, ErrUnreadable
	}
	counts, err := t.leaves(ctx, r, ls, redact, unredact, caller, dlp)
	if err != nil {
		return nil, nil, err
	}
	if dlp {
		// There is nowhere safe to put a token in an instruction, so a hit stops the body.
		rules := detect.SetFor(t.Rules, t.Engine, r.VaultID)
		if rules == nil {
			return nil, nil, detect.ErrRulesNotReady
		}
		for _, p := range procs {
			if active, _ := rules.Split(rules.ScanFor("proxy", "", p, "")); len(active) > 0 {
				return nil, nil, ErrUnreadable
			}
		}
	}
	// Set may run twice on a leaf, with rules and then detection. Only the last edit stands.
	last := map[int]*xmlEdit{}
	for _, e := range edits {
		last[e.start] = e
	}
	ordered := make([]*xmlEdit, 0, len(last))
	for _, e := range last {
		ordered = append(ordered, e)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].start < ordered[j].start })
	var out bytes.Buffer
	pos := 0
	for _, e := range ordered {
		if e.start < pos {
			return nil, nil, fmt.Errorf("overlapping edits")
		}
		out.Write(body[pos:e.start])
		out.WriteString(e.text)
		pos = e.end
	}
	out.Write(body[pos:])
	return out.Bytes(), counts, nil
}

// unescapeXML reads an attribute's raw value the way an XML parser would.
func unescapeXML(raw []byte, out *string) error {
	d := xml.NewDecoder(bytes.NewReader(append(append([]byte("<a>"), raw...), []byte("</a>")...)))
	d.Strict = true
	var b strings.Builder
	for {
		tok, err := d.RawToken()
		if errors.Is(err, io.EOF) {
			*out = b.String()
			return nil
		}
		if err != nil {
			return err
		}
		switch v := tok.(type) {
		case xml.CharData:
			b.Write(v)
		case xml.StartElement:
			if v.Name.Local != "a" {
				return ErrUnreadable
			}
		case xml.EndElement:
			if v.Name.Local != "a" {
				return ErrUnreadable
			}
		default:
			return ErrUnreadable
		}
	}
}

// headersNotScanned carry credentials or plumbing, not customer data. A rule can still name one.
var headersNotScanned = map[string]bool{
	"Authorization": true, "Proxy-Authorization": true, "Content-Type": true, "Content-Length": true, "Content-Encoding": true,
	"Accept": true, "Accept-Encoding": true, "Accept-Language": true, "Accept-Charset": true, "Date": true, "Host": true,
	"If-Match": true, "If-None-Match": true, "If-Modified-Since": true, "If-Unmodified-Since": true, "Range": true, "Cache-Control": true,
	"Pragma": true, "Traceparent": true, "Tracestate": true, "Etag": true, "Last-Modified": true, "Server": true, "Vary": true,
}

func headerPath(name string) string { return "header:" + http.CanonicalHeaderKey(name) }

func headerRules(rules []HeaderRule) []PathRule {
	out := make([]PathRule, 0, len(rules))
	for _, h := range rules {
		out = append(out, PathRule{Path: headerPath(h.Header), Field: h.Field})
	}
	return out
}

// Headers applies rules and detection to one set of headers.
func (t *Transformer) Headers(ctx context.Context, r *ProxyRoute, h http.Header, redact, unredact []HeaderRule, caller string, dlp bool) (logproc.Counts, error) {
	if len(redact)+len(unredact) == 0 && !dlp {
		return logproc.Counts{}, nil
	}
	rr, ur := headerRules(redact), headerRules(unredact)
	named := map[string]bool{}
	for _, x := range append(append([]PathRule{}, rr...), ur...) {
		named[x.Path] = true
	}
	var ls []logproc.Leaf
	for k, vs := range h {
		c := http.CanonicalHeaderKey(k)
		if headersNotScanned[c] && !named[headerPath(c)] {
			continue
		}
		for i := range vs {
			i, vs := i, vs
			ls = append(ls, logproc.Leaf{Value: vs[i], Hint: strings.TrimPrefix(strings.ToLower(c), "x-"), Path: headerPath(c), Set: func(s string) { vs[i] = s }})
		}
	}
	return t.leaves(ctx, r, ls, rr, ur, caller, dlp)
}

// QueryDLP checks parameters no rule named. Those named have already been tokenized.
func (t *Transformer) QueryDLP(ctx context.Context, r *ProxyRoute, q url.Values) (logproc.Counts, error) {
	var ls []logproc.Leaf
	for k, vs := range q {
		for i := range vs {
			i, vs := i, vs
			ls = append(ls, logproc.Leaf{Value: vs[i], Hint: k, Path: "query:" + k, Set: func(s string) { vs[i] = s }})
		}
	}
	if len(ls) == 0 {
		return logproc.Counts{}, nil
	}
	return t.leaves(ctx, r, ls, nil, nil, "", true)
}
