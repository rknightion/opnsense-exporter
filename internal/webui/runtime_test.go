package webui

import "testing"

func TestRuntimeSampler_Stats(t *testing.T) {
	s := newRuntimeSampler(8)
	s.sample()
	s.sample()
	st := s.stats()
	if st.Goroutines <= 0 {
		t.Errorf("Goroutines=%d want >0", st.Goroutines)
	}
	if st.GOMAXPROCS <= 0 {
		t.Errorf("GOMAXPROCS=%d want >0", st.GOMAXPROCS)
	}
	if len(st.GoroutinesSeries) != 2 {
		t.Errorf("GoroutinesSeries len=%d want 2", len(st.GoroutinesSeries))
	}
	if len(st.HeapAllocSeries) != 2 {
		t.Errorf("HeapAllocSeries len=%d want 2", len(st.HeapAllocSeries))
	}
	if st.HeapAlloc == "" {
		t.Errorf("HeapAlloc empty; want a humanized size")
	}
	if st.HeapAllocBytes == 0 {
		t.Errorf("HeapAllocBytes=0 want >0")
	}
}

func TestRuntimeSampler_RingBounded(t *testing.T) {
	s := newRuntimeSampler(3)
	for i := 0; i < 6; i++ {
		s.sample()
	}
	if got := len(s.stats().GoroutinesSeries); got != 3 {
		t.Errorf("series len=%d want 3 (ring bounded)", got)
	}
}

func TestRuntimeSampler_GCRateSeriesLen(t *testing.T) {
	s := newRuntimeSampler(8)
	// GC rate is a delta between adjacent samples, so N samples yield N-1 rates.
	s.sample()
	s.sample()
	s.sample()
	if got := len(s.stats().GCRateSeries); got != 2 {
		t.Errorf("GCRateSeries len=%d want 2 (N-1 deltas)", got)
	}
}
