package options

import "testing"

func TestValidateMetricsPath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"default /metrics", "/metrics", false},
		{"root", "/", false},
		{"custom nested", "/opnsense/metrics", false},
		{"empty rejected (templated-blank flag)", "", true},
		{"missing leading slash rejected", "metrics", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateMetricsPath(tt.path); (err != nil) != tt.wantErr {
				t.Errorf("ValidateMetricsPath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}
