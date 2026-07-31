package opnsense

import "fmt"

// APICallError is an error returned by the OPNsense API
type APICallError struct {
	Endpoint   string
	Message    string
	StatusCode int

	// PartialDecode is true when the body was valid JSON whose SHAPE
	// disagreed with the target struct on one or more fields — encoding/json's
	// UnmarshalTypeError. The decoder records a type error and keeps going, so
	// by the time it returns, every field it did understand is already written
	// to the caller's struct: the data is usable, minus the fields that
	// mismatched.
	//
	// This exists so a caller that can degrade gracefully has the option, and
	// does not throw a whole payload away over one bad field. That is exactly
	// what #615 did — two mismodelled wear percentages made the entire
	// smartInfo body undecodable, which cost every per-device SMART metric on
	// the only box with a real disk.
	//
	// A malformed body (not JSON at all, or a shape mismatch at the very top
	// level) is NOT partial: nothing decoded, so there is nothing to keep.
	PartialDecode bool
}

func (e APICallError) Error() string {
	return fmt.Sprintf(
		"opnsense-client api call error: endpoint: %s; failed status code: %d; msg: %s", e.Endpoint, e.StatusCode, e.Message,
	)
}
