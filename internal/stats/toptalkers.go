package stats

import "sort"

// maxTrackedTalkers caps the number of distinct source addresses kept in
// memory. A port scan or spoofed-source flood can otherwise add a new entry
// per packet.
const maxTrackedTalkers = 1 << 16

// Talker is one IP address and the number of bytes it has sent.
type Talker struct {
	IP    string
	Bytes uint64
}

// TopTalkers accumulates bytes per source IP and reports the heaviest N.
// It has no lock of its own: Statistics guards it with its mutex.
type TopTalkers struct {
	n      int // how many talkers topN returns
	limit  int // maximum number of addresses tracked
	counts map[string]uint64
}

func newTopTalkers(n int) *TopTalkers {
	return &TopTalkers{n: n, limit: maxTrackedTalkers, counts: make(map[string]uint64)}
}

// add records bytes sent by ip. Packets without an IP address (non-IP
// traffic) are ignored.
func (t *TopTalkers) add(ip string, bytes uint64) {
	if ip == "" {
		return
	}
	if _, known := t.counts[ip]; !known && len(t.counts) >= t.limit {
		t.prune()
	}
	t.counts[ip] += bytes
}

// prune keeps the heaviest half of the tracked addresses and forgets the
// rest. Dropping half at once, instead of one entry per insertion, keeps the
// amortised cost of add constant.
func (t *TopTalkers) prune() {
	keep := t.sorted()
	if len(keep) > t.limit/2 {
		keep = keep[:t.limit/2]
	}
	t.counts = make(map[string]uint64, t.limit)
	for _, talker := range keep {
		t.counts[talker.IP] = talker.Bytes
	}
}

// topN returns up to n talkers, heaviest first.
func (t *TopTalkers) topN() []Talker {
	talkers := t.sorted()
	if len(talkers) > t.n {
		talkers = talkers[:t.n]
	}
	return talkers
}

// sorted returns every tracked talker ordered by bytes, descending. Ties are
// broken by address so the order is stable from one refresh to the next.
func (t *TopTalkers) sorted() []Talker {
	talkers := make([]Talker, 0, len(t.counts))
	for ip, b := range t.counts {
		talkers = append(talkers, Talker{IP: ip, Bytes: b})
	}
	sort.Slice(talkers, func(i, j int) bool {
		if talkers[i].Bytes != talkers[j].Bytes {
			return talkers[i].Bytes > talkers[j].Bytes
		}
		return talkers[i].IP < talkers[j].IP
	})
	return talkers
}
