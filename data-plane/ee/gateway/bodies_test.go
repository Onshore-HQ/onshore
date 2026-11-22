package gateway

import (
	"bytes"
	"context"
	"errors"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"onshore/data-plane/ee/logproc"
	"onshore/data-plane/internal/detect"
)

const (
	bvn   = "22333444558"
	phone = "08034445555"
)

func tr() *Transformer {
	t := &Transformer{Engine: detect.New(detect.Config{})}
	t.Tokenize = func(_ context.Context, _ *ProxyRoute, items []logproc.Item) ([]string, error) {
		out := make([]string, len(items))
		for i := range items {
			out[i] = "tok_x_ABCDEF"
		}
		return out, nil
	}
	t.Reveal = func(_ context.Context, _ *ProxyRoute, _ string, tokens []string) (map[string]string, error) {
		m := map[string]string{}
		for _, tk := range tokens {
			m[tk] = "plain & <value>"
		}
		return m, nil
	}
	return t
}

func run(t *testing.T, r *ProxyRoute, ct, body string, redact ...string) (string, error) {
	t.Helper()
	var rules []PathRule
	for _, p := range redact {
		rules = append(rules, PathRule{Path: p})
	}
	out, _, _, err := tr().Body(context.Background(), r, ct, "", []byte(body), rules, nil, "", r.DLP)
	return string(out), err
}

func wantClean(t *testing.T, out string, secrets ...string) {
	t.Helper()
	for _, s := range secrets {
		if strings.Contains(out, s) {
			t.Errorf("%q survived: %s", s, out)
		}
	}
}

func TestFormRules(t *testing.T) {
	r := &ProxyRoute{}
	out, err := run(t, r, "application/x-www-form-urlencoded", "bvn="+bvn+"&tier=gold&bvn=11122233344&customer%5Bbvn%5D=22999988877&items%5B0%5D%5Bid%5D=55566677788", "$.bvn", "$.customer.bvn", "$.items[*].id")
	if err != nil {
		t.Fatal(err)
	}
	wantClean(t, out, bvn, "11122233344", "22999988877", "55566677788")
	v, err := url.ParseQuery(out)
	if err != nil || v.Get("tier") != "gold" || len(v["bvn"]) != 2 {
		t.Fatalf("%v %s", err, out)
	}
}

func TestFormDetectionAndEncodingTricks(t *testing.T) {
	r := &ProxyRoute{DLP: true}
	for _, body := range []string{
		"note=my+bvn+is+" + bvn,
		"note=my%20bvn%20is%20%32%32%33%33%33%34%34%34%35%35%38",
		"a=1;note=bvn " + bvn,
		"bvn=" + bvn,
	} {
		out, err := run(t, r, "application/x-www-form-urlencoded", body)
		if err != nil {
			t.Fatal(err)
		}
		wantClean(t, out, bvn)
	}
	// A semicolon stays inside its value when forwarded, so an upstream cannot split it.
	out, _ := run(t, r, "application/x-www-form-urlencoded", "a=1;b=2")
	if out != "a=1%3Bb%3D2" {
		t.Errorf("not canonical: %s", out)
	}
	for _, bad := range []string{"a=%zz", "%zz=1", "a=\xff"} {
		if _, err := run(t, r, "application/x-www-form-urlencoded", bad); !errors.Is(err, ErrUnreadable) {
			t.Errorf("%q passed: %v", bad, err)
		}
	}
}

func soap(inner string) string {
	return `<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:k="urn:kyc"><soapenv:Header/><soapenv:Body>` + inner + `</soapenv:Body></soapenv:Envelope>`
}

func TestSOAPKeepsEverythingButTheValue(t *testing.T) {
	r := &ProxyRoute{}
	in := soap(`<k:Check id="7">  <k:BVN>` + bvn + `</k:BVN> <k:Tier>gold</k:Tier></k:Check>`)
	out, err := run(t, r, "text/xml; charset=utf-8", in, "$.Envelope.Body.Check.BVN")
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(in, bvn, "tok_x_ABCDEF", 1)
	if out != want {
		t.Errorf("\n got %s\nwant %s", out, want)
	}
}

func TestXMLAttributesCommentsCDATAAndEntities(t *testing.T) {
	r := &ProxyRoute{DLP: true}
	for name, in := range map[string]string{
		"text":      `<a><note>bvn ` + bvn + `</note></a>`,
		"element":   `<a><BVN>` + bvn + `</BVN></a>`,
		"attribute": `<a bvn="` + bvn + `"/>`,
		"single":    `<a note='bvn ` + bvn + `'/>`,
		"prefixed":  `<a xmlns:k="urn:k" k:bvn="` + bvn + `"/>`,
		"comment":   `<a><!-- bvn ` + bvn + ` --></a>`,
		"cdata":     `<a><note><![CDATA[bvn ` + bvn + `]]></note></a>`,
		"entity":    `<a><note>bvn &#50;&#50;333444558</note></a>`,
	} {
		out, err := run(t, r, "application/xml", in)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		wantClean(t, out, bvn, "&#50;&#50;333444558")
		if !strings.HasPrefix(out, "<a") {
			t.Errorf("%s: damaged: %s", name, out)
		}
	}
	out, err := run(t, &ProxyRoute{}, "application/xml", `<a><c id="`+bvn+`"/></a>`, "$.a.c.@id")
	if err != nil || strings.Contains(out, bvn) {
		t.Errorf("attribute rule: %v %s", err, out)
	}
}

func TestXMLRefusesWhatItCannotRead(t *testing.T) {
	r := &ProxyRoute{DLP: true}
	for name, in := range map[string]string{
		"doctype":     `<!DOCTYPE a [<!ENTITY x "22333444558">]><a>&x;</a>`,
		"unbalanced":  `<a><b></a>`,
		"truncated":   `<a><b>`,
		"not xml":     `{"bvn":"` + bvn + `"}`,
		"top text":    bvn,
		"entity":      `<a>&nope;</a>`,
		"encoding":    `<?xml version="1.0" encoding="UTF-16"?><a>x</a>`,
		"deep":        strings.Repeat("<a>", 300) + strings.Repeat("</a>", 300),
		"instruction": `<?secret bvn ` + bvn + `?><a>x</a>`,
	} {
		if out, err := run(t, r, "text/xml", in); err == nil {
			t.Errorf("%s passed: %s", name, out)
		}
	}
}

func TestRestoredValueIsEscapedInXML(t *testing.T) {
	out, _, _, err := tr().Body(context.Background(), &ProxyRoute{}, "text/xml", "", []byte(`<a><b>tok_x_1</b></a>`), nil, []PathRule{{Path: "$.a.b"}}, "caller", false)
	if err != nil || string(out) != `<a><b>plain &amp; &lt;value&gt;</b></a>` {
		t.Errorf("%v %s", err, out)
	}
}

func form(t *testing.T, build func(w *multipart.Writer)) (string, string) {
	t.Helper()
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	build(w)
	w.Close()
	return w.FormDataContentType(), b.String()
}

func file(t *testing.T, w *multipart.Writer, name, filename, ct string, data []byte) {
	t.Helper()
	h := map[string][]string{"Content-Disposition": {`form-data; name="` + name + `"; filename="` + filename + `"`}}
	if ct != "" {
		h["Content-Type"] = []string{ct}
	}
	p, err := w.CreatePart(h)
	if err != nil {
		t.Fatal(err)
	}
	p.Write(data)
}

var png = append([]byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A, 0}, []byte(bvn)...)

func TestMultipartFieldsTextFilesAndFileNames(t *testing.T) {
	ct, body := form(t, func(w *multipart.Writer) {
		w.WriteField("bvn", bvn)
		w.WriteField("tier", "gold")
		file(t, w, "upload", "statement_"+phone+".csv", "text/csv", []byte("name,phone\nada,"+phone+"\n"))
	})
	out, err := run(t, &ProxyRoute{DLP: true}, ct, body, "$.bvn")
	if err != nil {
		t.Fatal(err)
	}
	wantClean(t, out, bvn, phone)
	if !strings.Contains(out, "gold") || !strings.Contains(out, `name="upload"`) || !strings.Contains(out, "name,phone") {
		t.Error(out)
	}
}

func TestMultipartBinaryFollowsPolicy(t *testing.T) {
	ct, body := form(t, func(w *multipart.Writer) { file(t, w, "id", "id.png", "image/png", png) })
	if _, err := run(t, &ProxyRoute{DLP: true}, ct, body); !errors.Is(err, ErrFileRefused) {
		t.Errorf("the default must refuse: %v", err)
	}
	if out, err := run(t, &ProxyRoute{DLP: true, FilePolicy: FilePass}, ct, body); err != nil || !strings.Contains(out, bvn) {
		t.Errorf("an explicit pass passes: %v", err)
	}
	if _, err := run(t, &ProxyRoute{DLP: true, FilePolicy: FileRedact}, ct, body); !errors.Is(err, ErrFileRefused) {
		t.Errorf("no file service must not pass the file: %v", err)
	}
	tt := tr()
	tt.RedactFile = func(_ context.Context, _ *ProxyRoute, _ []byte) ([]byte, string, map[string]int, bool, error) {
		return []byte("\x89PNGclean\x00"), "image/png", map[string]int{"bvn": 1}, false, nil
	}
	out, _, counts, err := tt.Body(context.Background(), &ProxyRoute{DLP: true, FilePolicy: FileRedact}, ct, "", []byte(body), nil, nil, "", true)
	if err != nil || strings.Contains(string(out), bvn) || !strings.Contains(string(out), "clean") || counts[[2]string{"bvn", "redacted"}] != 1 {
		t.Errorf("%v %s %v", err, out, counts)
	}
	tt.RedactFile = func(_ context.Context, _ *ProxyRoute, _ []byte) ([]byte, string, map[string]int, bool, error) {
		return []byte("x"), "image/png", nil, true, nil
	}
	if _, _, _, err := tt.Body(context.Background(), &ProxyRoute{DLP: true, FilePolicy: FileRedact}, ct, "", []byte(body), nil, nil, "", true); !errors.Is(err, ErrFileRefused) {
		t.Errorf("a low-confidence read must not pass: %v", err)
	}
}

func TestMultipartRefusesTricks(t *testing.T) {
	r := &ProxyRoute{DLP: true, FilePolicy: FilePass}
	const b = "XBOUND"
	ct := "multipart/form-data; boundary=" + b
	for name, body := range map[string]string{
		"base64":    "--" + b + "\r\nContent-Disposition: form-data; name=\"a\"\r\nContent-Transfer-Encoding: base64\r\n\r\nMjIzMzM0NDQ1NTg=\r\n--" + b + "--\r\n",
		"qp":        "--" + b + "\r\nContent-Disposition: form-data; name=\"a\"\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n=32=32\r\n--" + b + "--\r\n",
		"nested":    "--" + b + "\r\nContent-Disposition: form-data; name=\"a\"\r\nContent-Type: multipart/mixed; boundary=y\r\n\r\n--y--\r\n--" + b + "--\r\n",
		"no name":   "--" + b + "\r\nContent-Disposition: form-data\r\n\r\nx\r\n--" + b + "--\r\n",
		"truncated": "--" + b + "\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nbvn " + bvn,
	} {
		if out, err := run(t, r, ct, body); err == nil {
			t.Errorf("%s passed: %s", name, out)
		}
	}
	if _, err := run(t, r, "multipart/form-data", "x"); err == nil {
		t.Error("no boundary passed")
	}
	if _, err := run(t, r, "multipart/mixed; boundary=x", "x"); err == nil {
		t.Error("another multipart type passed")
	}
	// Junk around the parts and extra part headers do not reach the upstream.
	out, err := run(t, r, ct, "preamble "+bvn+"\r\n--"+b+"\r\nContent-Disposition: form-data; name=\"a\"\r\nX-Hidden: "+bvn+"\r\n\r\nok\r\n--"+b+"--\r\nepilogue "+bvn)
	if err != nil {
		t.Fatal(err)
	}
	wantClean(t, out, bvn, "X-Hidden")
}

func TestARuleNamingAFileIsNotIgnored(t *testing.T) {
	ct, body := form(t, func(w *multipart.Writer) { file(t, w, "id", "id.png", "image/png", png) })
	if _, err := run(t, &ProxyRoute{FilePolicy: FilePass}, ct, body, "$.id"); err == nil {
		t.Error("a rule on an unreadable part passed")
	}
}

func TestPlainTextAndWholeFiles(t *testing.T) {
	r := &ProxyRoute{DLP: true}
	out, err := run(t, r, "text/plain", "my bvn is "+bvn)
	if err != nil {
		t.Fatal(err)
	}
	wantClean(t, out, bvn)
	if _, err := run(t, &ProxyRoute{}, "text/plain", "my bvn is "+bvn, "$.bvn"); !errors.Is(err, ErrNotJSON) {
		t.Errorf("a field rule on plain text: %v", err)
	}
	// JSON with the wrong label is read as JSON.
	if out, err := run(t, &ProxyRoute{}, "text/plain", `{"bvn":"`+bvn+`"}`, "$.bvn"); err != nil || strings.Contains(out, bvn) {
		t.Errorf("%v %s", err, out)
	}
	// What the bytes are decides, whatever the label says.
	if out, err := run(t, r, "image/png", "bvn "+bvn); err != nil || strings.Contains(out, bvn) {
		t.Errorf("text labelled as an image: %v %s", err, out)
	}
	for _, ct := range []string{"application/octet-stream", "image/png", "application/pdf", "application/zip"} {
		if _, err := run(t, r, ct, string(png)); !errors.Is(err, ErrFileRefused) {
			t.Errorf("%s: %v", ct, err)
		}
	}
	if _, err := run(t, r, "not/a/type;;", "x"); !errors.Is(err, ErrUnreadable) {
		t.Errorf("bad type: %v", err)
	}
}

func TestCompressedBodyIsRefused(t *testing.T) {
	_, _, _, err := tr().Body(context.Background(), &ProxyRoute{DLP: true}, "text/plain", "gzip", []byte("\x1f\x8b"), nil, nil, "", true)
	if !errors.Is(err, ErrEncoded) {
		t.Errorf("%v", err)
	}
}

func TestNoRulesNoDetectionPassesUnread(t *testing.T) {
	out, _, _, err := tr().Body(context.Background(), &ProxyRoute{}, "application/zip", "gzip", png, nil, nil, "", false)
	if err != nil || !bytes.Equal(out, png) {
		t.Errorf("%v", err)
	}
}

func TestHeaders(t *testing.T) {
	h := http.Header{"X-Customer-Bvn": {bvn}, "X-Note": {"call " + phone}, "Authorization": {"Bearer " + bvn}, "X-Allowed": {phone}, "X-Plain": {"gold"}}
	r := &ProxyRoute{DLP: true, DLPExcludedHeaders: []string{"x-allowed"}}
	if _, err := tr().Headers(context.Background(), r, h, []HeaderRule{{Header: "x-customer-bvn"}}, nil, "", true); err != nil {
		t.Fatal(err)
	}
	if h.Get("X-Customer-Bvn") != "tok_x_ABCDEF" {
		t.Error("the named header kept its value")
	}
	if strings.Contains(h.Get("X-Note"), phone) {
		t.Error("detection missed a header")
	}
	if !strings.Contains(h.Get("Authorization"), bvn) {
		t.Error("credentials must pass through unscanned")
	}
	if h.Get("X-Allowed") != phone || h.Get("X-Plain") != "gold" {
		t.Error("an excluded or clean header changed")
	}
}

func TestRestoredHeaderCannotInjectAnother(t *testing.T) {
	tt := tr()
	tt.Reveal = func(_ context.Context, _ *ProxyRoute, _ string, tokens []string) (map[string]string, error) {
		return map[string]string{tokens[0]: "x\r\nX-Evil: 1"}, nil
	}
	h := http.Header{"X-Token": {"tok_1"}}
	if _, err := tt.Headers(context.Background(), &ProxyRoute{}, h, nil, []HeaderRule{{Header: "X-Token"}}, "caller", false); err != nil {
		t.Fatal(err)
	}
	if h.Get("X-Token") != "tok_1" {
		t.Errorf("injected: %q", h.Get("X-Token"))
	}
}

func TestQueryDetection(t *testing.T) {
	q := url.Values{"note": {"bvn " + bvn}, "page": {"2"}, "ok": {phone}}
	if _, err := tr().QueryDLP(context.Background(), &ProxyRoute{DLP: true, DLPExcludedParams: []string{"ok"}}, q); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(q.Get("note"), bvn) || q.Get("page") != "2" || q.Get("ok") != phone {
		t.Errorf("%v", q)
	}
}

// Each of these holds a BVN that byte-level detection cannot see.
func TestEncodingsThatHideAValue(t *testing.T) {
	r := &ProxyRoute{DLP: true}
	utf16 := "2\x002\x003\x003\x003\x004\x004\x004\x005\x005\x008\x00"
	for name, c := range map[string][2]string{
		"UTF-16 as text":  {"text/plain", utf16},
		"UTF-16 labelled": {"text/plain; charset=utf-16", "bvn " + bvn},
		"UTF-7 labelled":  {"text/plain; charset=utf-7", "+ADI-" + bvn},
		"form charset":    {"application/x-www-form-urlencoded; charset=utf-16", "a=1"},
		"XML charset":     {"text/xml; charset=utf-7", "<a>x</a>"},
		"JSON charset":    {"application/json; charset=utf-16", "{}"},
		"NUL in a form":   {"application/x-www-form-urlencoded", "note=2%002%003%003%003"},
	} {
		if out, err := run(t, r, c[0], c[1]); err == nil {
			t.Errorf("%s passed: %q", name, out)
		}
	}
	for _, cs := range []string{"utf-8", "UTF-8", "iso-8859-1", "us-ascii"} {
		out, err := run(t, r, "text/plain; charset="+cs, "bvn "+bvn)
		if err != nil || strings.Contains(out, bvn) {
			t.Errorf("%s: %v %s", cs, err, out)
		}
	}
}
