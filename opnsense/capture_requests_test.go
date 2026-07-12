package opnsense

import (
	"encoding/json"
	"strings"
	"testing"
)

// Every POST endpoint must have a capture request (so the live canary can
// probe it), and only the two genuinely parameterized endpoints may need a
// runtime-resolved value.
func TestCaptureRequestsCoverPostEndpoints(t *testing.T) {
	for name := range postEndpoints {
		req, ok := CaptureRequestFor(name)
		if !ok {
			t.Errorf("POST endpoint %q has no capture request", name)
			continue
		}
		switch req.ContentType {
		case "application/json":
			body := req.Body
			if req.Parameterized {
				body = strings.ReplaceAll(body, "%s", "x")
			}
			if !json.Valid([]byte(body)) {
				t.Errorf("capture body for %q is not valid JSON: %s", name, body)
			}
		case "application/x-www-form-urlencoded":
			// empty body is fine (smartList)
		default:
			t.Errorf("capture request for %q has unexpected content type %q", name, req.ContentType)
		}
	}

	for name := range captureRequests {
		if _, ok := postEndpoints[name]; !ok {
			t.Errorf("capture request %q is not a POST endpoint — GET endpoints need no body", name)
		}
	}

	wantParameterized := map[EndpointName]bool{"smartInfo": true, "ipsecPhase2": true}
	for name, req := range captureRequests {
		if req.Parameterized != wantParameterized[name] {
			t.Errorf("endpoint %q Parameterized = %v, want %v", name, req.Parameterized, wantParameterized[name])
		}
		if req.Parameterized && !strings.Contains(req.Body, "%s") {
			t.Errorf("parameterized endpoint %q body has no %%s placeholder: %s", name, req.Body)
		}
	}
}
