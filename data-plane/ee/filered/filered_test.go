package filered

import (
	"bytes"
	"context"
	"image"
	"strings"
	"testing"

	"onshore/data-plane/internal/detect"
)

func TestSniff(t *testing.T) {
	cases := map[string]string{"%PDF-1.7 x": "pdf", "\x89PNG\r\n": "image", "\xff\xd8\xff\xe0": "image", "RIFF\x00\x00\x00\x00WAVEfmt ": "audio", "hello, world": "text", "MZ\x00\x00binary": ""}
	for in, want := range cases {
		if got := sniff([]byte(in)); got != want {
			t.Errorf("%q = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeSpoken(t *testing.T) {
	cases := map[string]string{
		"my number is zero eight zero three one two three four five six seven": "my number is 08031234567",
		"my BVN is double two one two three, four five six seven eight nine":   "my BVN is 22123456789",
		"I have 2 children and one dog":                                        "I have 2 children and 1 dog",
		"triple seven":                                                         "777",
	}
	for in, want := range cases {
		if got := NormalizeSpoken(in); got != want {
			t.Errorf("%q = %q, want %q", in, got, want)
		}
	}
}

func TestTextRedaction(t *testing.T) {
	r := &Redactor{Engine: detect.New(detect.Config{})}
	res, err := r.Redact(context.Background(), []byte("name,bvn\nAda,22123456789\n"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(res.Body, []byte("22123456789")) || res.Counts["ng_11_digit_id"]+res.Counts["bvn"] == 0 {
		t.Fatalf("%s %+v", res.Body, res.Counts)
	}
}

func TestUnknownBinaryRefused(t *testing.T) {
	r := &Redactor{Engine: detect.New(detect.Config{}), TmpDir: t.TempDir()}
	if _, err := r.Redact(context.Background(), []byte("MZ\x00\x00binary")); err != ErrUnsupported {
		t.Fatalf("err=%v", err)
	}
}

func TestBoxesCoverOnlyTheEntity(t *testing.T) {
	r := &Redactor{Engine: detect.New(detect.Config{})}
	counts := map[string]int{}
	words := []word{{10, 10, 40, 12, 1, 95, "BVN"}, {60, 10, 120, 12, 1, 95, "22123456789"}, {200, 10, 40, 12, 1, 95, "thanks"}}
	boxes := r.boxes(words, counts)
	if len(boxes) != 1 || boxes[0].Min.X != 57 || counts["bvn"] != 1 {
		t.Fatalf("%+v %+v", boxes, counts)
	}
}

func TestBuiltPDFHasNoTextLayer(t *testing.T) {
	out := buildPDF([][]byte{[]byte("fakejpeg")}, []image.Point{{100, 100}}, 200)
	if !bytes.HasPrefix(out, []byte("%PDF-")) || strings.Contains(string(out), "/Font") || strings.Contains(string(out), "/Info") {
		t.Fatal(string(out))
	}
}
