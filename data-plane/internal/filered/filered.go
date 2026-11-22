// Package filered redacts documents, images and recordings. PDFs and images are
// rasterised and OCR'd, boxes are painted over the pixels, and a PDF is rebuilt from
// those pixels, so no hidden text layer can survive. Audio is transcribed, and the
// segments holding identifiers are silenced.
//
// It runs tesseract, poppler, ffmpeg and whisper as subprocesses on untrusted files,
// so its container has no database, no key service and no outbound network.
package filered

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/jpeg"
	_ "image/png"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"onshore/data-plane/internal/detect"
	"onshore/data-plane/internal/logproc"
)

// MaxPages bounds PDF rendering.
const MaxPages = 200

// Result is a redacted file plus what was found. It never holds a found value.
type Result struct {
	Body        []byte
	ContentType string
	Counts      map[string]int
	// LowConfidence means OCR or transcription was too uncertain to trust the absence
	// of findings; a person should check this file.
	LowConfidence bool
	Transcript    string
}

// Redactor runs the tools.
type Redactor struct {
	Engine *detect.Engine
	Rules  detect.RuleSets
	// set is the rule set of one request; see forVault.
	set          *detect.RuleSet
	TmpDir       string
	WhisperModel string
	Timeout      time.Duration
}

// forVault returns a copy bound to a vault's rule set, or an error before rules load.
func (r *Redactor) forVault(vault string) (*Redactor, error) {
	rs := detect.SetFor(r.Rules, r.Engine, vault)
	if rs == nil {
		return nil, detect.ErrRulesNotReady
	}
	c := *r
	c.set = rs
	return &c, nil
}

// scan returns what must be redacted. Files have no per-module setting of their own, so
// they follow the API's, and shadow entities change nothing here as everywhere.
func (r *Redactor) scan(text, hint string, counts map[string]int) []detect.Entity {
	if r.set == nil {
		return r.Engine.ScanWithHint(text, hint)
	}
	active, observed := r.set.Split(r.set.ScanFor("api", "", text, hint))
	for _, e := range observed {
		counts[string(e.Type)+":"+detect.CountLabel(e)]++
	}
	return active
}

func (r *Redactor) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...) // #nosec fixed tools; file paths are generated here
	cmd.Env = []string{"OMP_THREAD_LIMIT=2", "PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/tmp"}
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		// Tool messages can quote document text, so they are not kept.
		return nil, fmt.Errorf("%s failed", name)
	}
	return stdout.Bytes(), nil
}

// Redact dispatches on the detected type, not on what the caller claims.
func (r *Redactor) Redact(ctx context.Context, body []byte) (*Result, error) {
	if r.set == nil {
		r = &Redactor{Engine: r.Engine, Rules: nil, TmpDir: r.TmpDir, WhisperModel: r.WhisperModel, set: detect.BaseRuleSet(r.Engine)}
	}
	timeout := r.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dir, err := os.MkdirTemp(r.TmpDir, "rvf")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir) // the upload and all derived files go with the request
	switch sniff(body) {
	case "pdf":
		return r.pdf(ctx, dir, body)
	case "image":
		return r.image(ctx, dir, body)
	case "audio":
		return r.audio(ctx, dir, body)
	case "text":
		return r.text(body), nil
	}
	return nil, ErrUnsupported
}

// ErrUnsupported means the type is unknown, so the file cannot be vouched for.
var ErrUnsupported = errors.New("unsupported file type")

func sniff(b []byte) string {
	switch {
	case bytes.HasPrefix(b, []byte("%PDF-")):
		return "pdf"
	case bytes.HasPrefix(b, []byte{0x89, 'P', 'N', 'G'}), bytes.HasPrefix(b, []byte{0xFF, 0xD8, 0xFF}), bytes.HasPrefix(b, []byte("II*\x00")), bytes.HasPrefix(b, []byte("MM\x00*")):
		return "image"
	case bytes.HasPrefix(b, []byte("RIFF")) && len(b) > 12 && string(b[8:12]) == "WAVE", bytes.HasPrefix(b, []byte("ID3")), bytes.HasPrefix(b, []byte("OggS")), bytes.HasPrefix(b, []byte("fLaC")), bytes.HasPrefix(b, []byte("FORM")), len(b) > 12 && string(b[4:8]) == "ftyp", len(b) > 2 && b[0] == 0xFF && b[1]&0xE0 == 0xE0:
		return "audio"
	}
	sample := b
	if len(sample) > 8192 {
		sample = sample[:8192]
	}
	if !bytes.ContainsRune(sample, 0) {
		return "text"
	}
	return ""
}

func (r *Redactor) text(body []byte) *Result {
	counts := map[string]int{}
	pl := logproc.ParseBody(body)
	for _, l := range pl.Leaves {
		active, observed := r.set.Split(r.set.ScanFor("api", l.Path, l.Value, l.Hint))
		for _, e := range observed {
			counts[string(e.Type)+":"+detect.CountLabel(e)]++
		}
		if len(active) == 0 {
			continue
		}
		l.Set(detect.Replace(l.Value, active, func(e detect.Entity, v string) string {
			counts[string(e.Type)]++
			return r.set.MaskValue(e.Type, v)
		}))
	}
	out, err := pl.Encode(nil)
	if err != nil {
		out = []byte{}
	}
	return &Result{Body: out, ContentType: "text/plain; charset=utf-8", Counts: counts}
}

// word is one OCR word with its box.
type word struct {
	left, top, w, h, line int
	conf                  float64
	text                  string
}

// ocr runs tesseract and returns its words.
func (r *Redactor) ocr(ctx context.Context, path string) ([]word, error) {
	out, err := r.run(ctx, "tesseract", path, "stdout", "--psm", "3", "-l", "eng", "tsv")
	if err != nil {
		return nil, err
	}
	rd := csv.NewReader(bytes.NewReader(out))
	rd.Comma, rd.LazyQuotes, rd.FieldsPerRecord = '\t', true, -1
	rows, err := rd.ReadAll()
	if err != nil {
		return nil, errors.New("could not read the OCR output")
	}
	var words []word
	for i, row := range rows {
		if i == 0 || len(row) < 12 || strings.TrimSpace(row[11]) == "" {
			continue
		}
		n := func(j int) int { v, _ := strconv.Atoi(row[j]); return v }
		conf, _ := strconv.ParseFloat(row[10], 64)
		// page, block, paragraph and line together identify a line.
		words = append(words, word{n(6), n(7), n(8), n(9), n(2)*1_000_000 + n(3)*1_000 + n(4), conf, row[11]})
	}
	return words, nil
}

// boxes finds the pixels to paint: words overlapping any entity found on a line, or
// on a line with its neighbour, since labels often sit above their values.
func (r *Redactor) boxes(words []word, counts map[string]int) []image.Rectangle {
	byLine := map[int][]word{}
	var lines []int
	for _, w := range words {
		if _, ok := byLine[w.line]; !ok {
			lines = append(lines, w.line)
		}
		byLine[w.line] = append(byLine[w.line], w)
	}
	sort.Ints(lines)
	var out []image.Rectangle
	prev := ""
	for _, ln := range lines {
		var b strings.Builder
		spans := make([][2]int, 0, len(byLine[ln]))
		for _, w := range byLine[ln] {
			start := b.Len()
			b.WriteString(w.text)
			spans = append(spans, [2]int{start, b.Len()})
			b.WriteByte(' ')
		}
		text := b.String()
		for _, e := range r.scan(text, prev, counts) {
			counts[string(e.Type)]++
			for i, s := range spans {
				if e.Start < s[1] && e.End > s[0] {
					w := byLine[ln][i]
					out = append(out, image.Rect(w.left-3, w.top-3, w.left+w.w+3, w.top+w.h+3))
				}
			}
		}
		prev = text
	}
	return out
}

// paint draws boxes and re-encodes, which also drops EXIF and other metadata.
func paint(path string, boxes []image.Rectangle) (image.Image, error) {
	f, err := os.Open(path) // #nosec generated path
	if err != nil {
		return nil, err
	}
	defer f.Close()
	src, _, err := image.Decode(f)
	if err != nil {
		return nil, errors.New("could not read the image")
	}
	dst := image.NewRGBA(src.Bounds())
	draw.Draw(dst, dst.Bounds(), src, src.Bounds().Min, draw.Src)
	black := image.NewUniform(color.Black)
	for _, b := range boxes {
		draw.Draw(dst, b.Intersect(dst.Bounds()), black, image.Point{}, draw.Src)
	}
	return dst, nil
}

func lowConfidence(words []word) bool {
	if len(words) == 0 {
		return true // nothing readable: could be a photo of a card, so it is not cleared
	}
	var sum float64
	for _, w := range words {
		sum += w.conf
	}
	return sum/float64(len(words)) < 60
}

func (r *Redactor) image(ctx context.Context, dir string, body []byte) (*Result, error) {
	in := filepath.Join(dir, "in")
	if err := os.WriteFile(in, body, 0o600); err != nil {
		return nil, err
	}
	// Normalise through a PNG first, so tesseract and Go decode the same pixels.
	png := filepath.Join(dir, "in.png")
	if _, err := r.run(ctx, "ffmpeg", "-loglevel", "error", "-y", "-i", in, "-frames:v", "1", png); err != nil {
		return nil, err
	}
	words, err := r.ocr(ctx, png)
	if err != nil {
		return nil, err
	}
	counts := map[string]int{}
	img, err := paint(png, r.boxes(words, counts))
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 88}); err != nil {
		return nil, err
	}
	return &Result{Body: buf.Bytes(), ContentType: "image/jpeg", Counts: counts, LowConfidence: lowConfidence(words)}, nil
}

func (r *Redactor) pdf(ctx context.Context, dir string, body []byte) (*Result, error) {
	in := filepath.Join(dir, "in.pdf")
	if err := os.WriteFile(in, body, 0o600); err != nil {
		return nil, err
	}
	if _, err := r.run(ctx, "pdftoppm", "-r", "200", "-png", "-f", "1", "-l", strconv.Itoa(MaxPages), in, filepath.Join(dir, "p")); err != nil {
		return nil, err
	}
	pages, err := filepath.Glob(filepath.Join(dir, "p-*.png"))
	if err != nil || len(pages) == 0 {
		return nil, errors.New("the PDF has no readable pages")
	}
	info, _ := r.run(ctx, "pdfinfo", in)
	if m := pagesRe.FindSubmatch(info); m != nil {
		if n, _ := strconv.Atoi(string(m[1])); n > MaxPages {
			return nil, fmt.Errorf("the PDF has more than %d pages", MaxPages)
		}
	}
	sort.Strings(pages)
	counts := map[string]int{}
	low := false
	var jpegs [][]byte
	var sizes []image.Point
	for _, p := range pages {
		words, err := r.ocr(ctx, p)
		if err != nil {
			return nil, err
		}
		low = low || lowConfidence(words)
		img, err := paint(p, r.boxes(words, counts))
		if err != nil {
			return nil, err
		}
		var buf bytes.Buffer
		if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 80}); err != nil {
			return nil, err
		}
		jpegs = append(jpegs, buf.Bytes())
		sizes = append(sizes, img.Bounds().Size())
	}
	return &Result{Body: buildPDF(jpegs, sizes, 200), ContentType: "application/pdf", Counts: counts, LowConfidence: low}, nil
}

var pagesRe = regexp.MustCompile(`Pages:\s+(\d+)`)

// buildPDF writes a minimal image-only PDF, one JPEG per page. There is no text
// layer, no metadata and nothing carried over from the original file.
func buildPDF(jpegs [][]byte, sizes []image.Point, dpi int) []byte {
	var b bytes.Buffer
	var offsets []int
	obj := func(body []byte) {
		offsets = append(offsets, b.Len())
		fmt.Fprintf(&b, "%d 0 obj\n", len(offsets))
		b.Write(body)
		b.WriteString("\nendobj\n")
	}
	b.WriteString("%PDF-1.4\n")
	n := len(jpegs)
	var kids strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&kids, "%d 0 R ", 3+i*3)
	}
	obj([]byte("<< /Type /Catalog /Pages 2 0 R >>"))
	obj([]byte(fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", kids.String(), n)))
	for i, j := range jpegs {
		w, h := float64(sizes[i].X)*72/float64(dpi), float64(sizes[i].Y)*72/float64(dpi)
		page, content, img := 3+i*3, 4+i*3, 5+i*3
		_ = page
		obj([]byte(fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.2f %.2f] /Contents %d 0 R /Resources << /XObject << /I %d 0 R >> >> >>", w, h, content, img)))
		c := fmt.Sprintf("q %.2f 0 0 %.2f 0 0 cm /I Do Q", w, h)
		obj([]byte(fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(c), c)))
		var im bytes.Buffer
		fmt.Fprintf(&im, "<< /Type /XObject /Subtype /Image /Width %d /Height %d /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length %d >>\nstream\n", sizes[i].X, sizes[i].Y, len(j))
		im.Write(j)
		im.WriteString("\nendstream")
		obj(im.Bytes())
	}
	xref := b.Len()
	fmt.Fprintf(&b, "xref\n0 %d\n0000000000 65535 f \n", len(offsets)+1)
	for _, o := range offsets {
		fmt.Fprintf(&b, "%010d 00000 n \n", o)
	}
	fmt.Fprintf(&b, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(offsets)+1, xref)
	return b.Bytes()
}

// spoken turns spoken numbers into digits, since callers read identifiers aloud
// ("zero eight zero three", "double two").
var spokenDigits = map[string]string{"zero": "0", "oh": "0", "o": "0", "one": "1", "two": "2", "three": "3", "four": "4", "five": "5", "six": "6", "seven": "7", "eight": "8", "nine": "9"}

// NormalizeSpoken joins runs of spoken and written digits, so that the detector can
// see them. Nigerian speakers commonly say "double" and "triple".
func NormalizeSpoken(text string) string {
	fields := strings.Fields(text)
	var out []string
	var run strings.Builder
	flush := func() {
		if run.Len() > 0 {
			out = append(out, run.String())
			run.Reset()
		}
	}
	for i := 0; i < len(fields); i++ {
		w := strings.ToLower(strings.Trim(fields[i], ".,;:!?-"))
		mult := 1
		if (w == "double" || w == "triple") && i+1 < len(fields) {
			next := strings.ToLower(strings.Trim(fields[i+1], ".,;:!?-"))
			if d, ok := spokenDigits[next]; ok || isDigits(next) {
				if !ok {
					d = next
				}
				mult = 2
				if w == "triple" {
					mult = 3
				}
				run.WriteString(strings.Repeat(d, mult))
				i++
				continue
			}
		}
		if d, ok := spokenDigits[w]; ok {
			run.WriteString(d)
			continue
		}
		if isDigits(w) {
			run.WriteString(w)
			continue
		}
		flush()
		out = append(out, fields[i])
	}
	flush()
	return strings.Join(out, " ")
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

type whisperOut struct {
	Transcription []struct {
		Offsets struct {
			From int `json:"from"`
			To   int `json:"to"`
		} `json:"offsets"`
		Text string `json:"text"`
	} `json:"transcription"`
}

func (r *Redactor) audio(ctx context.Context, dir string, body []byte) (*Result, error) {
	if r.WhisperModel == "" {
		return nil, ErrUnsupported
	}
	in := filepath.Join(dir, "in")
	if err := os.WriteFile(in, body, 0o600); err != nil {
		return nil, err
	}
	wav := filepath.Join(dir, "in.wav")
	if _, err := r.run(ctx, "ffmpeg", "-loglevel", "error", "-y", "-i", in, "-vn", "-ar", "16000", "-ac", "1", "-c:a", "pcm_s16le", wav); err != nil {
		return nil, err
	}
	base := filepath.Join(dir, "t")
	if _, err := r.run(ctx, "whisper-cli", "-m", r.WhisperModel, "-f", wav, "-oj", "-of", base, "-np", "-l", "en", "-t", "2"); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(base + ".json") // #nosec generated path
	if err != nil {
		return nil, err
	}
	var w whisperOut
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, errors.New("could not read the transcript")
	}
	counts := map[string]int{}
	var filters []string
	var transcript strings.Builder
	prev := ""
	for _, seg := range w.Transcription {
		text := NormalizeSpoken(seg.Text)
		ents := r.scan(text, prev, counts)
		// A long digit run in speech is an identifier even with no label nearby.
		if len(ents) > 0 {
			from, to := float64(seg.Offsets.From)/1000-0.25, float64(seg.Offsets.To)/1000+0.25
			if from < 0 {
				from = 0
			}
			filters = append(filters, fmt.Sprintf("volume=enable='between(t,%.2f,%.2f)':volume=0", from, to))
		}
		transcript.WriteString(detect.Replace(text, ents, func(e detect.Entity, _ string) string {
			counts[string(e.Type)]++
			return "[" + string(e.Type) + " removed]"
		}))
		transcript.WriteByte('\n')
		prev = text
	}
	out := filepath.Join(dir, "out.wav")
	args := []string{"-loglevel", "error", "-y", "-i", wav, "-map_metadata", "-1"}
	if len(filters) > 0 {
		args = append(args, "-af", strings.Join(filters, ","))
	}
	if _, err := r.run(ctx, "ffmpeg", append(args, out)...); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(out) // #nosec generated path
	if err != nil {
		return nil, err
	}
	return &Result{Body: b, ContentType: "audio/wav", Counts: counts, LowConfidence: len(w.Transcription) == 0, Transcript: transcript.String()}, nil
}
