package logship

import (
	"sync"
	"time"
)

// LogLimiter rate-limits repeated log lines keyed by a string: Allow reports true at
// most once per interval per key, so a flapping source cannot flood the log while a
// newly-appearing key is still reported promptly.
//
// It is exported for the push receivers, which live in subpackages
// (internal/logship/zenarmor) and need the same throttle on the same terms.
type LogLimiter struct {
	mu       sync.Mutex
	last     map[string]time.Time
	interval time.Duration
	maxKeys  int
}

// NewLogLimiter builds a limiter reporting a given key at most once per interval and
// holding at most maxKeys keys.
//
// maxKeys is what makes the limiter safe for a key derived from the wire. The key map
// is the memory a key set costs, and an uncapped one keyed by a peer-controlled value
// is a leak that peer can drive — the hazard #280 forbids for metric labels, merely
// relocated from a label into a map. Callers whose keys are code-defined and bounded
// (the pipeline's source names) never reach the cap, so it costs them nothing.
func NewLogLimiter(interval time.Duration, maxKeys int) *LogLimiter {
	return &LogLimiter{last: map[string]time.Time{}, interval: interval, maxKeys: maxKeys}
}

// Allow reports whether key may be logged now, recording the decision when it may.
//
// At the cap it purges expired keys before refusing, so the cap bounds the keys held
// per interval rather than silencing every new key for the life of the process.
func (l *LogLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	t, tracked := l.last[key]
	if tracked && now.Sub(t) < l.interval {
		return false
	}
	// Only an untracked key can grow the map; refreshing a tracked one cannot.
	if !tracked && len(l.last) >= l.maxKeys {
		l.purgeExpired(now)
		if len(l.last) >= l.maxKeys {
			return false
		}
	}
	l.last[key] = now
	return true
}

// purgeExpired drops keys whose interval has elapsed. Caller holds l.mu.
func (l *LogLimiter) purgeExpired(now time.Time) {
	for k, t := range l.last {
		if now.Sub(t) >= l.interval {
			delete(l.last, k)
		}
	}
}
