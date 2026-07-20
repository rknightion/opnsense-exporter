package webui

import (
	"fmt"
	"runtime"
	"sync"
	"time"
)

// RuntimeStats is the process runtime snapshot rendered on the console Overview
// tab: the latest values plus bounded series for the ~10-minute trend charts
// (goroutines, heap-in-use, GC rate). It is filled by runtimeSampler.stats().
type RuntimeStats struct {
	Goroutines       int
	GOMAXPROCS       int
	HeapAlloc        string // humanized, e.g. "12M"
	HeapAllocBytes   uint64
	NumGC            uint32
	GoroutinesSeries []int     // oldest→newest, ≤ ring size
	HeapAllocSeries  []uint64  // oldest→newest, ≤ ring size
	GCRateSeries     []float64 // GC cycles/sec between adjacent samples (len = samples-1)
}

// runtimeSample is one observation of the Go runtime.
type runtimeSample struct {
	at         time.Time
	goroutines int
	heapAlloc  uint64
	numGC      uint32
}

// runtimeSampler keeps a bounded ring of runtime observations sampled on a
// background ticker, so the Overview tab can show a ~10-minute runtime trend
// without any live API call. It mirrors growthSampler's shape (immediate first
// sample, ticker, stop channel).
type runtimeSampler struct {
	mu   sync.Mutex
	ring []runtimeSample
	max  int
	stop chan struct{}
}

// newRuntimeSampler returns a sampler bounded at max observations (min 2).
func newRuntimeSampler(max int) *runtimeSampler {
	if max < 2 {
		max = 2
	}
	return &runtimeSampler{max: max}
}

// sample records one observation of the current runtime state. runtime.ReadMemStats
// stops the world briefly; the sampler runs on a slow ticker so this is negligible.
func (r *runtimeSampler) sample() {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	s := runtimeSample{
		at:         time.Now(),
		goroutines: runtime.NumGoroutine(),
		heapAlloc:  ms.HeapAlloc,
		numGC:      ms.NumGC,
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ring = append(r.ring, s)
	if len(r.ring) > r.max {
		r.ring = r.ring[len(r.ring)-r.max:]
	}
}

// stats returns the latest observation plus the trend series. GCRateSeries holds
// one rate per adjacent-sample gap (NumGC delta / seconds elapsed), so it is one
// shorter than the value series. Returns a zero value when no sample exists yet.
func (r *runtimeSampler) stats() RuntimeStats {
	r.mu.Lock()
	defer r.mu.Unlock()

	st := RuntimeStats{GOMAXPROCS: runtime.GOMAXPROCS(0)}
	n := len(r.ring)
	if n == 0 {
		return st
	}

	last := r.ring[n-1]
	st.Goroutines = last.goroutines
	st.HeapAllocBytes = last.heapAlloc
	st.HeapAlloc = humanizeBytes(last.heapAlloc)
	st.NumGC = last.numGC

	st.GoroutinesSeries = make([]int, n)
	st.HeapAllocSeries = make([]uint64, n)
	for i, s := range r.ring {
		st.GoroutinesSeries[i] = s.goroutines
		st.HeapAllocSeries[i] = s.heapAlloc
	}
	if n >= 2 {
		st.GCRateSeries = make([]float64, 0, n-1)
		for i := 1; i < n; i++ {
			secs := r.ring[i].at.Sub(r.ring[i-1].at).Seconds()
			rate := 0.0
			if secs > 0 && r.ring[i].numGC >= r.ring[i-1].numGC {
				rate = float64(r.ring[i].numGC-r.ring[i-1].numGC) / secs
			}
			st.GCRateSeries = append(st.GCRateSeries, rate)
		}
	}
	return st
}

// start begins background sampling every interval until close is called. It
// takes one sample immediately so a freshly-loaded page isn't blank. Safe to
// call once; a non-positive interval is a no-op.
func (r *runtimeSampler) start(interval time.Duration) {
	if interval <= 0 || r.stop != nil {
		return
	}
	r.stop = make(chan struct{})
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			r.sample()
			select {
			case <-r.stop:
				return
			case <-t.C:
			}
		}
	}()
}

// close stops background sampling.
func (r *runtimeSampler) close() {
	if r.stop != nil {
		close(r.stop)
		r.stop = nil
	}
}

// humanizeBytes renders a byte count compactly for the runtime cards (K/M/G).
func humanizeBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%dB", b)
	}
	switch {
	case b < unit*unit:
		return fmt.Sprintf("%.0fK", float64(b)/unit)
	case b < unit*unit*unit:
		return fmt.Sprintf("%.1fM", float64(b)/(unit*unit))
	default:
		return fmt.Sprintf("%.2fG", float64(b)/(unit*unit*unit))
	}
}
