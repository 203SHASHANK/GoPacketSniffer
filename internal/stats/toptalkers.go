package stats

import "sort"

// Talker represents a single IP address and its traffic volume.
type Talker struct {
	IP    string
	Bytes uint64
}

// TopTalkers tracks the top N source IPs by bytes sent.
type TopTalkers struct {
	n      int
	counts map[string]uint64
}

func newTopTalkers(n int) *TopTalkers {
	return &TopTalkers{n: n, counts: make(map[string]uint64)}
}

// add records bytes for the given IP. Must be called with the parent lock held.
func (t *TopTalkers) add(ip string, bytes uint64) {
	if ip == "" {
		return
	}
	t.counts[ip] += bytes
}

// topN returns the top N IPs sorted descending by bytes.
// Must be called with the parent lock held.
func (t *TopTalkers) topN() []Talker {
	talkers := make([]Talker, 0, len(t.counts))
	for ip, b := range t.counts {
		talkers = append(talkers, Talker{IP: ip, Bytes: b})
	}
	sort.Slice(talkers, func(i, j int) bool {
		return talkers[i].Bytes > talkers[j].Bytes
	})
	if len(talkers) > t.n {
		talkers = talkers[:t.n]
	}
	return talkers
}
