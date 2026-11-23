// Package nlp asks the install's language-model service (spaCy, Hugging Face
// transformers or Stanza) for names and places in text, on top of the patterns,
// checksums and name lists. It is a paid feature under the Onshore Commercial Licence.
//
// A service that imports this package gets the finder when RV_NLP_URL is set. The
// model service runs inside the install, over mutual TLS, with no outbound network,
// so text never leaves it. If the service can't be reached, detection carries on
// with the patterns alone and a warning is logged at most once a minute.
package nlp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"onshore/data-plane/internal/detect"
	"onshore/data-plane/internal/rules"
	"onshore/data-plane/internal/tlsutil"
)

// MaxText bounds what is sent in one call; longer text is sent in pieces.
const MaxText = 20_000

// Labels map the service's labels to Onshore's entity types.
var Labels = map[string]detect.EntityType{"person": detect.PersonName, "place": "address"}

// Client calls the model service.
type Client struct {
	URL      string
	HTTP     *http.Client
	MinScore float64

	mu       sync.Mutex
	lastWarn time.Time
}

type entity struct {
	Start int     `json:"start"` // byte offsets into the UTF-8 text
	End   int     `json:"end"`
	Label string  `json:"label"`
	Score float64 `json:"score"`
}

// Find implements detect.ModelFinder.
func (c *Client) Find(text string) ([]detect.Entity, error) {
	var out []detect.Entity
	for off := 0; off < len(text); {
		end := cut(text, off)
		found, err := c.find(text[off:end])
		if err != nil {
			c.warn(err)
			return nil, err
		}
		for _, e := range found {
			t, ok := Labels[e.Label]
			if !ok || e.Score < c.MinScore || e.Start < 0 || e.End > end-off || e.Start >= e.End {
				continue
			}
			out = append(out, detect.Entity{Type: t, Start: off + e.Start, End: off + e.End, Score: e.Score})
		}
		off = end
	}
	return out, nil
}

// cut ends a piece at a line break or space near MaxText, never inside a character.
func cut(text string, off int) int {
	end := off + MaxText
	if end >= len(text) {
		return len(text)
	}
	for i := end; i > off+MaxText/2; i-- {
		if text[i] == '\n' || text[i] == ' ' {
			return i
		}
	}
	for end > off && end < len(text) && text[end]&0xC0 == 0x80 {
		end--
	}
	return end
}

func (c *Client) find(text string) ([]entity, error) {
	body, _ := json.Marshal(map[string]string{"text": text})
	resp, err := c.HTTP.Post(c.URL+"/v1/entities", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("the language model service can't be reached")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the language model service answered %d", resp.StatusCode)
	}
	var r struct {
		Entities []entity `json:"entities"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&r); err != nil {
		return nil, errors.New("the language model service sent an unreadable answer")
	}
	return r.Entities, nil
}

func (c *Client) warn(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.lastWarn) < time.Minute {
		return
	}
	c.lastWarn = time.Now()
	// Never the text: only that the model couldn't add to the patterns.
	log.Printf("language models unavailable, detection uses patterns only: %v", err)
}

var (
	once   sync.Once
	shared *Client
)

// FromEnv builds the client once from RV_NLP_URL, or returns nil when it's unset.
func FromEnv() detect.ModelFinder {
	once.Do(func() {
		url := os.Getenv("RV_NLP_URL")
		if url == "" {
			return
		}
		timeout := 3 * time.Second
		if v, err := time.ParseDuration(os.Getenv("RV_NLP_TIMEOUT")); err == nil && v > 0 {
			timeout = v
		}
		hc, err := tlsutil.Client(os.Getenv("RV_TLS_CERT"), os.Getenv("RV_TLS_KEY"), os.Getenv("RV_TLS_CLIENT_CA"), timeout)
		if err != nil {
			log.Printf("language models off: %v", err)
			return
		}
		min := 0.6
		if v, err := strconv.ParseFloat(os.Getenv("RV_NLP_MIN_SCORE"), 64); err == nil && v > 0 && v <= 1 {
			min = v
		}
		shared = &Client{URL: url, HTTP: hc, MinScore: min}
	})
	if shared == nil {
		return nil // a typed nil would look switched on
	}
	return shared
}

func init() { rules.NewModelFinder = FromEnv }
