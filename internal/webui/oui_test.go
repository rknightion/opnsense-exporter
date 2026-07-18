package webui

import "testing"

func TestLookupOUI_KnownPrefix(t *testing.T) {
	// B827EB is Raspberry Pi in the embedded table; the lookup must normalise
	// the colon-separated form and match on the first 6 hex digits.
	if got := LookupOUI("B8:27:EB:12:34:56"); got == "" {
		t.Fatalf("want a vendor for a known prefix, got empty")
	}
	if got := LookupOUI("b8-27-eb-12-34-56"); got == "" {
		t.Fatalf("want a vendor for a known prefix (dash+lowercase), got empty")
	}
}

func TestLookupOUI_Misses(t *testing.T) {
	if got := LookupOUI("zz"); got != "" {
		t.Fatalf("garbage/short input should miss, got %q", got)
	}
	if got := LookupOUI(""); got != "" {
		t.Fatalf("empty input should miss, got %q", got)
	}
	if got := LookupOUI("FFFFFF000000"); got != "" {
		t.Fatalf("unassigned prefix should miss, got %q", got)
	}
}
