package logship

import (
	"reflect"
	"testing"
)

func TestReservedAttributeKeys(t *testing.T) {
	want := []string{"opnsense.source", "service.name", "service.instance.id"}
	if !reflect.DeepEqual(reservedAttributeKeys, want) {
		t.Fatalf("reserved keys drifted: got %v want %v", reservedAttributeKeys, want)
	}
}

func TestSanitizeAttributes_StripsReserved(t *testing.T) {
	in := map[string]string{
		"opnsense.source":     "forged",
		"service.name":        "forged",
		"service.instance.id": "forged",
		"src":                 "10.0.0.1",
		"dstport":             "443",
	}
	got := sanitizeAttributes(in)
	for _, k := range reservedAttributeKeys {
		if _, ok := got[k]; ok {
			t.Fatalf("reserved key %q survived sanitization", k)
		}
	}
	if got["src"] != "10.0.0.1" || got["dstport"] != "443" {
		t.Fatalf("non-reserved attributes lost: %v", got)
	}
	// Caller's map must not be mutated.
	if _, ok := in["opnsense.source"]; !ok {
		t.Fatal("sanitizeAttributes mutated the caller's map")
	}
}

func TestSanitizeAttributes_PassthroughUnchanged(t *testing.T) {
	in := map[string]string{"src": "10.0.0.1"}
	got := sanitizeAttributes(in)
	// No reserved key present => same map returned (no allocation).
	if reflect.ValueOf(got).Pointer() != reflect.ValueOf(in).Pointer() {
		t.Fatal("expected the original map to be returned when no reserved key present")
	}
}

func TestSanitizeAttributes_Nil(t *testing.T) {
	if sanitizeAttributes(nil) != nil {
		t.Fatal("nil input should yield nil output")
	}
}

func TestSeverityString(t *testing.T) {
	cases := map[Severity]string{
		SeverityInfo:  "info",
		SeverityTrace: "trace",
		SeverityDebug: "debug",
		SeverityWarn:  "warn",
		SeverityError: "error",
		SeverityFatal: "fatal",
	}
	for sv, want := range cases {
		if got := sv.String(); got != want {
			t.Errorf("Severity(%d).String()=%q want %q", sv, got, want)
		}
	}
}
