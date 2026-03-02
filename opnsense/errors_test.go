package opnsense

import (
	"strings"
	"testing"
)

func TestAPICallError_Error(t *testing.T) {
	err := APICallError{
		Endpoint:   "api/core/service/search",
		Message:    "connection refused",
		StatusCode: 503,
	}

	got := err.Error()

	if !strings.Contains(got, "api/core/service/search") {
		t.Errorf("expected error to contain endpoint, got: %s", got)
	}
	if !strings.Contains(got, "503") {
		t.Errorf("expected error to contain status code, got: %s", got)
	}
	if !strings.Contains(got, "connection refused") {
		t.Errorf("expected error to contain message, got: %s", got)
	}
}

func TestAPICallError_Error_ZeroStatusCode(t *testing.T) {
	err := APICallError{
		Endpoint:   "test",
		Message:    "network error",
		StatusCode: 0,
	}

	got := err.Error()

	if !strings.Contains(got, "0") {
		t.Errorf("expected error to contain status code 0, got: %s", got)
	}
}
