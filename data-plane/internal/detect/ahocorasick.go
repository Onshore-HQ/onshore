package detect

// matcher is a byte-level Aho-Corasick automaton over lower-cased keywords.
type matcher struct {
	next [][256]int32
	fail []int32
	out  [][]int32 // keyword indices ending at each state
	lens []int
}

func newMatcher(words []string) *matcher {
	m := &matcher{next: make([][256]int32, 1), fail: []int32{0}, out: [][]int32{nil}}
	for i := range m.next[0] {
		m.next[0][i] = -1
	}
	for idx, w := range words {
		m.lens = append(m.lens, len(w))
		s := int32(0)
		for i := 0; i < len(w); i++ {
			c := w[i]
			if m.next[s][c] < 0 {
				var row [256]int32
				for j := range row {
					row[j] = -1
				}
				m.next = append(m.next, row)
				m.fail = append(m.fail, 0)
				m.out = append(m.out, nil)
				m.next[s][c] = int32(len(m.next) - 1)
			}
			s = m.next[s][c]
		}
		m.out[s] = append(m.out[s], int32(idx))
	}
	var queue []int32
	for c := 0; c < 256; c++ {
		if n := m.next[0][c]; n >= 0 {
			queue = append(queue, n)
		} else {
			m.next[0][c] = 0
		}
	}
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		for c := 0; c < 256; c++ {
			n := m.next[s][c]
			if n < 0 {
				m.next[s][c] = m.next[m.fail[s]][c]
				continue
			}
			m.fail[n] = m.next[m.fail[s]][c]
			m.out[n] = append(m.out[n], m.out[m.fail[n]]...)
			queue = append(queue, n)
		}
	}
	return m
}

// scan calls emit(keywordIndex, start, end) for every keyword occurrence.
func (m *matcher) scan(lower []byte, emit func(idx, start, end int)) {
	s := int32(0)
	for i, c := range lower {
		s = m.next[s][c]
		for _, idx := range m.out[s] {
			emit(int(idx), i+1-m.lens[idx], i+1)
		}
	}
}
