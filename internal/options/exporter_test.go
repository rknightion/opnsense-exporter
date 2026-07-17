package options

import "testing"

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
