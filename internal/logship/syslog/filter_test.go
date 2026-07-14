package syslog

import "testing"

// The default must ship EVERYTHING. Filtering is opt-in: a receiver that quietly
// decides what the user does not need is worse than one that costs a little more.
func TestFilterDefaultShipsEverything(t *testing.T) {
	f := NewFilter(nil, nil, 0, false)
	if f.Enabled() {
		t.Error("a filter with no configuration must report itself disabled")
	}
	for _, prog := range []string{"filterlog", "radvd", "totally-unknown"} {
		for sev := 0; sev <= 7; sev++ {
			if !f.Allow(prog, sev) {
				t.Errorf("default filter dropped %s at severity %d", prog, sev)
			}
		}
	}
	// A nil filter (never configured) must also pass everything, not panic.
	var nilf *Filter
	if !nilf.Allow("anything", 7) {
		t.Error("a nil filter must pass everything")
	}
}

func TestFilterExcludePrograms(t *testing.T) {
	f := NewFilter(nil, []string{"radvd", "cron"}, 0, false)
	if f.Allow("radvd", 6) {
		t.Error("radvd should be excluded")
	}
	if !f.Allow("filterlog", 6) {
		t.Error("filterlog should still ship")
	}
}

func TestFilterIncludeIsAnAllowlist(t *testing.T) {
	f := NewFilter([]string{"filterlog", "audit"}, nil, 0, false)
	if !f.Allow("audit", 6) {
		t.Error("an included program must ship")
	}
	if f.Allow("haproxy", 6) {
		t.Error("with an include list set, everything else must be dropped")
	}
}

// SYSLOG SEVERITY IS INVERTED: 0 is emerg, 7 is debug. Getting the comparison
// backwards would drop exactly the lines an operator cares about and keep the noise.
func TestFilterMinSeverityKeepsTheWorstNotTheLeast(t *testing.T) {
	// notice (5): keep emerg..notice, drop info (6) and debug (7).
	f := NewFilter(nil, nil, 5, true)
	for sev, want := range map[int]bool{
		0: true,  // emerg
		2: true,  // crit
		3: true,  // err
		4: true,  // warning
		5: true,  // notice
		6: false, // info
		7: false, // debug
	} {
		if got := f.Allow("anything", sev); got != want {
			t.Errorf("severity %d: Allow = %v, want %v (0=emerg is the WORST, 7=debug the least)", sev, got, want)
		}
	}
}

// The real-world case from the capture: radvd floods at debug and says nothing.
func TestFilterDropsRadvdDebugNoiseButKeepsItsWarnings(t *testing.T) {
	f := NewFilter(nil, nil, 5, true)
	if f.Allow("radvd", 7) {
		t.Error("radvd's debug timer noise should be dropped")
	}
	if !f.Allow("radvd", 3) {
		t.Error("radvd at error severity must still ship -- it stopped being noise")
	}
}
