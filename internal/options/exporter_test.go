package options

import (
	"testing"

	"github.com/alecthomas/kingpin/v2"
)

func TestValidateMetricsPath(t *testing.T) {
	// reserved mirrors the fixed routes main.go registers alongside the metrics
	// handler; reusing one for the metrics path panics net/http.ServeMux at startup.
	reserved := []string{"/-/healthy", "/-/ready"}
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"default /metrics", "/metrics", false},
		{"root", "/", false},
		{"custom nested", "/opnsense/metrics", false},
		{"custom /prometheus", "/prometheus", false},
		{"empty rejected (templated-blank flag)", "", true},
		{"missing leading slash rejected", "metrics", true},
		{"reserved /-/healthy rejected", "/-/healthy", true},
		{"reserved /-/ready rejected", "/-/ready", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateMetricsPath(tt.path, reserved...); (err != nil) != tt.wantErr {
				t.Errorf("ValidateMetricsPath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

// TestScrapeTimeoutOffsetFlagIsRemoved covers #439. --exporter.scrape-timeout-offset
// was subtracted from Prometheus' X-Prometheus-Scrape-Timeout-Seconds header to derive
// a collection deadline. After #336 serving /metrics replays an in-memory snapshot and
// makes no OPNsense API call, so the derived deadline bounded nothing and the flag was
// inert. It is removed outright rather than deprecated: keeping it would preserve a
// knob whose own help text describes behaviour the exporter does not have.
func TestScrapeTimeoutOffsetFlagIsRemoved(t *testing.T) {
	RegisterAllFlags()
	for _, f := range kingpin.CommandLine.Model().Flags {
		if f.Name == "exporter.scrape-timeout-offset" {
			t.Fatalf("--exporter.scrape-timeout-offset is still registered: %q", f.Help)
		}
	}
}
