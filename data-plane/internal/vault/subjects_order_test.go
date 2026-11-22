package vault

import (
	"strings"
	"testing"
)

func TestSubjectOrderIsAFixedList(t *testing.T) {
	for _, c := range []struct{ sort, dir, want string }{
		{"", "", "s.created_at DESC"},
		{"reveals_30d", "asc", "reveals_30d ASC"},
		{"last_accessed", "desc", "last_accessed DESC"},
		{"field_count", "", "field_count DESC"},
	} {
		got, err := subjectOrder(c.sort, c.dir)
		if err != nil || !strings.HasPrefix(got, c.want+" NULLS LAST") {
			t.Errorf("subjectOrder(%q, %q) = %q, %v", c.sort, c.dir, got, err)
		}
	}
	for _, c := range [][2]string{{"ref", ""}, {"s.id; DROP TABLE data.subjects", ""}, {"created_at", "asc; --"}, {"(select 1)", "desc"}} {
		if got, err := subjectOrder(c[0], c[1]); err == nil {
			t.Errorf("subjectOrder(%q, %q) was accepted: %q", c[0], c[1], got)
		}
	}
}
