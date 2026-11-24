package payload

import (
	"bytes"
	"encoding/json"
	"strings"

	collogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	common "go.opentelemetry.io/proto/otlp/common/v1"
	logs "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func keyHasDigit(k string) bool { return strings.ContainsAny(k, "0123456789") }

// ---- generic JSON ------------------------------------------------------------

func walkJSON(v any, path string, record int, set func(any), leaves *[]Leaf) {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			k, child := k, child
			childPath := path + "." + k
			walkJSON(child, childPath, record, func(n any) { t[k] = n }, leaves)
			// Identifiers do turn up as map keys ({"22123456789": {...}}).
			if keyHasDigit(k) {
				*leaves = append(*leaves, Leaf{Value: k, Hint: HintFromPath(path), Record: record, Set: func(nk string) {
					t[nk] = t[k]
					delete(t, k)
				}})
			}
		}
	case []any:
		for i, child := range t {
			i := i
			walkJSON(child, path, record, func(n any) { t[i] = n }, leaves)
		}
	case string:
		*leaves = append(*leaves, Leaf{Value: t, Hint: HintFromPath(path), Path: path, Record: record, Set: func(s string) { set(s) }})
	case json.Number:
		*leaves = append(*leaves, Leaf{Value: t.String(), Hint: HintFromPath(path), Path: path, Record: record, Set: func(s string) { set(s) }})
	}
}

func decodeNumber(b []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	if d.More() {
		return nil, errTrailing
	}
	return v, nil
}

type stringError string

func (e stringError) Error() string { return string(e) }

const errTrailing = stringError("trailing data")

func encodeJSON(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(b.Bytes(), "\n"), nil
}

// Payload is a parsed body ready for Process and then Encode.
type Payload struct {
	Leaves []Leaf
	Encode func(dropped map[int]bool) ([]byte, error)
}

// ParseBody understands a JSON document, NDJSON, or plain text lines. Anything
// unparseable is scanned as text, so a malformed body is still redacted.
func ParseBody(body []byte) *Payload {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
		if v, err := decodeNumber(trimmed); err == nil {
			return parseJSONDoc(v)
		}
		if p := parseNDJSON(trimmed); p != nil {
			return p
		}
	}
	return parseText(body)
}

func parseJSONDoc(v any) *Payload {
	p := &Payload{}
	holder := []any{v}
	if arr, ok := v.([]any); ok {
		for i := range arr {
			i := i
			walkJSON(arr[i], "$", i, func(n any) { arr[i] = n }, &p.Leaves)
		}
		p.Encode = func(dropped map[int]bool) ([]byte, error) {
			kept := make([]any, 0, len(arr))
			for i, r := range arr {
				if !dropped[i] {
					kept = append(kept, r)
				}
			}
			return encodeJSON(kept)
		}
		return p
	}
	walkJSON(v, "$", 0, func(n any) { holder[0] = n }, &p.Leaves)
	p.Encode = func(dropped map[int]bool) ([]byte, error) {
		if dropped[0] {
			return []byte("{}"), nil
		}
		return encodeJSON(holder[0])
	}
	return p
}

func parseNDJSON(body []byte) *Payload {
	lines := bytes.Split(body, []byte("\n"))
	docs := make([]any, 0, len(lines))
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		v, err := decodeNumber(line)
		if err != nil {
			return nil
		}
		docs = append(docs, v)
	}
	p := &Payload{}
	for i := range docs {
		i := i
		walkJSON(docs[i], "$", i, func(n any) { docs[i] = n }, &p.Leaves)
	}
	p.Encode = func(dropped map[int]bool) ([]byte, error) {
		var b bytes.Buffer
		for i, d := range docs {
			if dropped[i] {
				continue
			}
			line, err := encodeJSON(d)
			if err != nil {
				return nil, err
			}
			b.Write(line)
			b.WriteByte('\n')
		}
		return b.Bytes(), nil
	}
	return p
}

func parseText(body []byte) *Payload {
	lines := strings.Split(string(body), "\n")
	p := &Payload{}
	for i := range lines {
		i := i
		if lines[i] != "" {
			p.Leaves = append(p.Leaves, Leaf{Value: lines[i], Record: i, Set: func(s string) { lines[i] = s }})
		}
	}
	p.Encode = func(dropped map[int]bool) ([]byte, error) {
		kept := make([]string, 0, len(lines))
		for i, l := range lines {
			if !dropped[i] {
				kept = append(kept, l)
			}
		}
		return []byte(strings.Join(kept, "\n")), nil
	}
	return p
}

// ---- OTLP --------------------------------------------------------------------

func walkAny(v *common.AnyValue, path string, record int, leaves *[]Leaf) {
	if v == nil {
		return
	}
	switch t := v.Value.(type) {
	case *common.AnyValue_StringValue:
		*leaves = append(*leaves, Leaf{Value: t.StringValue, Hint: HintFromPath(path), Path: path, Record: record, Set: func(s string) { t.StringValue = s }})
	case *common.AnyValue_IntValue:
		// A BVN logged as an integer is still a BVN.
		*leaves = append(*leaves, Leaf{Value: formatInt(t.IntValue), Hint: HintFromPath(path), Path: path, Record: record, Set: func(s string) {
			v.Value = &common.AnyValue_StringValue{StringValue: s}
		}})
	case *common.AnyValue_ArrayValue:
		if t.ArrayValue != nil {
			for _, c := range t.ArrayValue.Values {
				walkAny(c, path, record, leaves)
			}
		}
	case *common.AnyValue_KvlistValue:
		if t.KvlistValue != nil {
			walkAttrs(t.KvlistValue.Values, path, record, leaves)
		}
	}
}

func formatInt(i int64) string {
	b, _ := json.Marshal(i)
	return string(b)
}

func walkAttrs(attrs []*common.KeyValue, path string, record int, leaves *[]Leaf) {
	for _, kv := range attrs {
		kv := kv
		walkAny(kv.Value, path+"."+kv.Key, record, leaves)
		if keyHasDigit(kv.Key) {
			*leaves = append(*leaves, Leaf{Value: kv.Key, Hint: HintFromPath(path), Record: record, Set: func(s string) { kv.Key = s }})
		}
	}
}

// ParseOTLP handles application/x-protobuf and application/json.
func ParseOTLP(body []byte, isJSON bool) (*Payload, error) {
	var req collogs.ExportLogsServiceRequest
	var err error
	if isJSON {
		err = protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(body, &req)
	} else {
		err = proto.Unmarshal(body, &req)
	}
	if err != nil {
		return nil, err
	}
	p := &Payload{}
	var records []*logs.LogRecord
	for _, rl := range req.ResourceLogs {
		if rl.Resource != nil {
			walkAttrs(rl.Resource.Attributes, "$.resource", -1, &p.Leaves)
		}
		for _, sl := range rl.ScopeLogs {
			if sl.Scope != nil {
				walkAttrs(sl.Scope.Attributes, "$.scope", -1, &p.Leaves)
			}
			for _, lr := range sl.LogRecords {
				i := len(records)
				records = append(records, lr)
				walkAny(lr.Body, "$.body", i, &p.Leaves)
				walkAttrs(lr.Attributes, "$.attributes", i, &p.Leaves)
			}
		}
	}
	p.Encode = func(dropped map[int]bool) ([]byte, error) {
		if len(dropped) > 0 {
			drop := map[*logs.LogRecord]bool{}
			for i := range dropped {
				if i >= 0 {
					drop[records[i]] = true
				}
			}
			for _, rl := range req.ResourceLogs {
				for _, sl := range rl.ScopeLogs {
					kept := sl.LogRecords[:0]
					for _, lr := range sl.LogRecords {
						if !drop[lr] {
							kept = append(kept, lr)
						}
					}
					sl.LogRecords = kept
				}
			}
		}
		if isJSON {
			return protojson.Marshal(&req)
		}
		return proto.Marshal(&req)
	}
	return p, nil
}

// ParseOTLPSignal handles traces and metrics, which carry identifiers in attributes,
// span names and event names. Records are never dropped from these: a drop rule masks.
func ParseOTLPSignal(msg proto.Message, body []byte, isJSON bool) (*Payload, error) {
	var err error
	if isJSON {
		err = protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(body, msg)
	} else {
		err = proto.Unmarshal(body, msg)
	}
	if err != nil {
		return nil, err
	}
	p := &Payload{}
	collectLeaves(msg, &p.Leaves)
	p.Encode = func(map[int]bool) ([]byte, error) {
		if isJSON {
			return protojson.Marshal(msg)
		}
		return proto.Marshal(msg)
	}
	return p, nil
}

// collectLeaves walks any OTLP message by reflection, so that every metric point type
// is covered, including ones added later.
func collectLeaves(m proto.Message, leaves *[]Leaf) {
	switch t := m.(type) {
	case *common.KeyValue:
		walkAttrs([]*common.KeyValue{t}, "$", -1, leaves)
		return
	case *common.AnyValue:
		walkAny(t, "$", -1, leaves)
		return
	}
	r := m.ProtoReflect()
	r.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch {
		case fd.IsList() && fd.Message() != nil:
			l := v.List()
			for i := 0; i < l.Len(); i++ {
				collectLeaves(l.Get(i).Message().Interface(), leaves)
			}
		case fd.Message() != nil && !fd.IsMap():
			collectLeaves(v.Message().Interface(), leaves)
		case fd.Kind() == protoreflect.StringKind && !fd.IsList() && !fd.IsMap() && scanStringField[string(fd.Name())]:
			fd := fd
			*leaves = append(*leaves, Leaf{Value: v.String(), Record: -1, Set: func(s string) { r.Set(fd, protoreflect.ValueOfString(s)) }})
		}
		return true
	})
}

// scanStringField names plain string fields that can hold free text. Ids and schema
// URLs are left alone.
var scanStringField = map[string]bool{"name": true, "message": true, "description": true, "trace_state": false}
