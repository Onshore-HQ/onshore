package license

import (
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// Editions, lowest first. Paid features live in directories named "ee" and are
// under the Onshore Commercial Licence: free for development and testing,
// production needs a subscription. See ee/LICENSE at the repository root.
const (
	Free        = "free"
	Business    = "business"
	Enterprise  = "enterprise"
	Development = "development" // a build without the licence key: everything on, for development and testing only
)

var rank = map[string]int{Free: 0, Business: 1, Enterprise: 2, Development: 3}

// State is the edition this install runs as, and why.
type State struct {
	Edition string
	Licence *Licence // nil without a valid licence
	Expired bool
	Note    string
}

// Has reports whether the edition includes features of the given level.
func (s State) Has(level string) bool { return rank[s.Edition] >= rank[level] }

var (
	once    sync.Once
	current State
)

// Current reads RV_LICENCE once and returns the edition. Expired licences keep
// their edition: expiry never cuts features or data, the product only warns.
// RV_EDITION can lower the edition (for testing what Community or Business
// customers see); it can never raise it.
func Current() State {
	once.Do(func() { current = resolve(os.Getenv("RV_LICENCE"), os.Getenv("RV_EDITION"), time.Now()) })
	return current
}

func resolve(blob, override string, now time.Time) State {
	var s State
	key, err := BuiltInKey()
	switch {
	case err != nil:
		s = State{Edition: Development, Note: "development build: paid features are on for development and testing only"}
	case blob == "":
		s = State{Edition: Free}
	default:
		l, verr := Verify(blob, key)
		if verr != nil {
			s = State{Edition: Free, Note: "the installed licence is not valid"}
			break
		}
		s = State{Edition: Free, Licence: &l, Expired: l.Expired(now)}
		for _, m := range l.Modules {
			if rank[m] > rank[s.Edition] && m != Development {
				s.Edition = m
			}
		}
		if s.Expired {
			s.Note = "the licence has expired; renew it to keep receiving updates"
		}
	}
	if o := strings.TrimSpace(strings.ToLower(override)); o != "" {
		if r, ok := rank[o]; ok && o != Development && r < rank[s.Edition] {
			s.Note = "lowered from " + s.Edition + " by RV_EDITION, for testing"
			s.Edition = o
		}
	}
	return s
}

// SetForTest replaces the current edition and returns a function that restores it.
func SetForTest(s State) (restore func()) {
	Current()
	old := current
	current = s
	return func() { current = old }
}

// LogStartup prints the edition once when a service starts.
func LogStartup(service string) {
	s := Current()
	if s.Note != "" {
		log.Printf("%s: Onshore %s edition (%s)", service, s.Edition, s.Note)
		return
	}
	log.Printf("%s: Onshore %s edition", service, s.Edition)
}

// IsTestVault reports whether a vault ID belongs to a test vault. Paid features
// are free on test vaults, because they hold only made-up data.
func IsTestVault(id string) bool { return strings.HasPrefix(id, "v_test_") }
