package options

import "testing"

// These tests exercise applyEnableAllAvailable (#517) against SYNTHETIC
// enableFlagBinding values rather than the real package-level kingpin flags:
// kingpin flags are global and parsed once per test binary, so mutating them
// here would leak state into every other test in this package. The synthetic
// bindings use the same Flag names as real CollectorFlags entries so the
// Reason/Subsystem lookups exercise the real metadata table.

func testBinding(flag string, value, userSet *bool, apply func(*CollectorsDisableSwitch)) enableFlagBinding {
	return enableFlagBinding{flag: flag, value: value, userSet: userSet, apply: apply}
}

func TestApplyEnableAllAvailable_Disabled_IsNoOp(t *testing.T) {
	var smart bool
	bindings := []enableFlagBinding{
		testBinding("exporter.enable-smart", &smart, new(bool), func(s *CollectorsDisableSwitch) { s.SMART = true }),
	}
	switches, enabled := applyEnableAllAvailable(false, bindings, CollectorsDisableSwitch{}, nil, false)
	if switches.SMART {
		t.Error("expected SMART to stay false when --exporter.enable-all-available is off")
	}
	if enabled != nil {
		t.Errorf("expected no AutoEnabledFeature entries, got %v", enabled)
	}
}

func TestApplyEnableAllAvailable_EnablesUntouchedSwitch(t *testing.T) {
	var smart bool
	bindings := []enableFlagBinding{
		testBinding("exporter.enable-smart", &smart, new(bool), func(s *CollectorsDisableSwitch) { s.SMART = true }),
	}
	switches, enabled := applyEnableAllAvailable(true, bindings, CollectorsDisableSwitch{}, nil, false)
	if !switches.SMART {
		t.Error("expected SMART to be turned on")
	}
	if len(enabled) != 1 || enabled[0].Flag != "exporter.enable-smart" {
		t.Fatalf("expected exactly one AutoEnabledFeature for exporter.enable-smart, got %v", enabled)
	}
	if enabled[0].Subsystem != "smart" {
		t.Errorf("Subsystem = %q, want %q (from the real CollectorFlags table)", enabled[0].Subsystem, "smart")
	}
	if enabled[0].Reason == "" {
		t.Error("expected a non-empty Reason, sourced from the real CollectorFlags table")
	}
}

// TestApplyEnableAllAvailable_ExplicitCLIFlagWins covers the issue's own
// requirement: "an operator who wants to opt back out of one collector can
// still pass --exporter.enable-<x>=false". Here that's modelled as userSet
// (kingpin's IsSetByUser) being true while the underlying value is false.
func TestApplyEnableAllAvailable_ExplicitCLIFlagWins(t *testing.T) {
	smartValue := false
	smartUserSet := true // operator explicitly passed --exporter.enable-smart=false
	bindings := []enableFlagBinding{
		testBinding("exporter.enable-smart", &smartValue, &smartUserSet, func(s *CollectorsDisableSwitch) { s.SMART = true }),
	}
	switches, enabled := applyEnableAllAvailable(true, bindings, CollectorsDisableSwitch{}, nil, false)
	if switches.SMART {
		t.Error("expected SMART to stay false: the operator's own --exporter.enable-smart=false must win")
	}
	if len(enabled) != 0 {
		t.Errorf("expected no AutoEnabledFeature for an explicitly-set flag, got %v", enabled)
	}
}

// TestApplyEnableAllAvailable_ExplicitEnvVarWins covers the same precedence
// rule for an env-var override, which kingpin's IsSetByUser callback never
// observes (it only fires for a CLI token) — explicitlySet() must still catch
// it via os.LookupEnv.
func TestApplyEnableAllAvailable_ExplicitEnvVarWins(t *testing.T) {
	t.Setenv("OPNSENSE_EXPORTER_ENABLE_SMART", "false")
	var smartValue bool // as if kingpin resolved the env var into the flag's own value
	bindings := []enableFlagBinding{
		{
			flag:  "exporter.enable-smart",
			envar: "OPNSENSE_EXPORTER_ENABLE_SMART",
			value: &smartValue,
			apply: func(s *CollectorsDisableSwitch) { s.SMART = true },
		},
	}
	switches, enabled := applyEnableAllAvailable(true, bindings, CollectorsDisableSwitch{}, nil, false)
	if switches.SMART {
		t.Error("expected SMART to stay false: the operator's own env var must win")
	}
	if len(enabled) != 0 {
		t.Errorf("expected no AutoEnabledFeature for an env-var-set flag, got %v", enabled)
	}
}

func TestApplyEnableAllAvailable_MultipleUntouchedSwitchesAllEnabled(t *testing.T) {
	var smart, tor, vnstat bool
	bindings := []enableFlagBinding{
		testBinding("exporter.enable-smart", &smart, new(bool), func(s *CollectorsDisableSwitch) { s.SMART = true }),
		testBinding("exporter.enable-tor", &tor, new(bool), func(s *CollectorsDisableSwitch) { s.Tor = true }),
		testBinding("exporter.enable-vnstat", &vnstat, new(bool), func(s *CollectorsDisableSwitch) { s.Vnstat = true }),
	}
	switches, enabled := applyEnableAllAvailable(true, bindings, CollectorsDisableSwitch{}, nil, false)
	if !switches.SMART || !switches.Tor || !switches.Vnstat {
		t.Errorf("expected all three switches enabled, got %+v", switches)
	}
	if len(enabled) != 3 {
		t.Fatalf("expected 3 AutoEnabledFeature entries, got %d: %v", len(enabled), enabled)
	}
}

func TestEnableFlagBindings_CoverRealCollectorFlagsEntries(t *testing.T) {
	// Every real enableFlagBinding must reference a Flag that CollectorFlags
	// actually declares with a Reason - otherwise --exporter.enable-all-available
	// would silently log an empty reason for a real flag.
	declared := map[string]CollectorFlag{}
	for _, cf := range CollectorFlags {
		declared[cf.Flag] = cf
	}
	for _, b := range enableFlagBindings {
		cf, ok := declared[b.flag]
		if !ok {
			t.Errorf("enableFlagBindings references %q, which has no CollectorFlags entry", b.flag)
			continue
		}
		if cf.Reason == "" {
			t.Errorf("CollectorFlags entry for %q has no Reason", b.flag)
		}
	}
}
