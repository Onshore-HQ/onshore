// Package payload reads request bodies (JSON, NDJSON, text and OTLP) as a list of
// scannable strings, and counts what detection found in them. The AI gateway, log
// pipelines, the HTTP proxy and the scanner share it.
package payload

import "strings"

// MaxLeafBytes bounds a single scanned value. Larger values are replaced when
// enforcing rather than forwarded unread.
const MaxLeafBytes = 1 << 20

// Item asks for a token.
type Item struct {
	Entity string `json:"entity,omitempty"`
	Field  string `json:"field,omitempty"` // a named vault field, for gateway path rules
	Value  string `json:"value"`
}

// Leaf is one scannable string in a payload.
type Leaf struct {
	Value  string
	Hint   string // key path, supplies context
	Path   string // $.a.b, matched against SensitivePaths
	Record int    // which line or record it belongs to
	Set    func(string)
}

// Counts tallies detections per entity and action.
type Counts map[[2]string]int64

// HintFromPath reduces a key path to its last segments for context scoring.
func HintFromPath(path string) string {
	parts := strings.Split(strings.TrimPrefix(path, "$."), ".")
	if len(parts) > 2 {
		parts = parts[len(parts)-2:]
	}
	return strings.Join(parts, " ")
}
