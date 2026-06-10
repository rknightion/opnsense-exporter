package opnsense

import (
	"encoding/json"
	"testing"
)

func TestFlexString_String(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"normal string", `"hello"`, "hello"},
		{"numeric string", `"1"`, "1"},
		{"zero string", `"0"`, "0"},
		{"empty string", `""`, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var fs flexString
			if err := json.Unmarshal([]byte(tc.input), &fs); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if fs.String() != tc.want {
				t.Errorf("got %q, want %q", fs.String(), tc.want)
			}
		})
	}
}

func TestFlexString_Number(t *testing.T) {
	var fs flexString
	if err := json.Unmarshal([]byte(`42`), &fs); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fs.String() != "42" {
		t.Errorf("got %q, want %q", fs.String(), "42")
	}
}

func TestFlexString_Bool(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{`true`, "true"},
		{`false`, "false"},
	}
	for _, tc := range tests {
		var fs flexString
		if err := json.Unmarshal([]byte(tc.input), &fs); err != nil {
			t.Fatalf("unexpected error for %s: %v", tc.input, err)
		}
		if fs.String() != tc.want {
			t.Errorf("input %s: got %q, want %q", tc.input, fs.String(), tc.want)
		}
	}
}

func TestFlexString_Null(t *testing.T) {
	var fs flexString
	if err := json.Unmarshal([]byte(`null`), &fs); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fs.String() != "" {
		t.Errorf("got %q, want empty string", fs.String())
	}
}

func TestFlexString_EmptyArray(t *testing.T) {
	var fs flexString
	if err := json.Unmarshal([]byte(`[]`), &fs); err != nil {
		t.Fatalf("unexpected error for empty array: %v", err)
	}
	if fs.String() != "" {
		t.Errorf("got %q, want empty string", fs.String())
	}
}

func TestFlexString_NonEmptyArray(t *testing.T) {
	// Any array (even non-empty) should decode to "" without error.
	var fs flexString
	if err := json.Unmarshal([]byte(`["a","b"]`), &fs); err != nil {
		t.Fatalf("unexpected error for non-empty array: %v", err)
	}
	if fs.String() != "" {
		t.Errorf("got %q, want empty string", fs.String())
	}
}

func TestFlexStringMap_Object(t *testing.T) {
	var fsm flexStringMap
	if err := json.Unmarshal([]byte(`{"em0":"LAN","em1":"IOT"}`), &fsm); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fsm["em0"] != "LAN" {
		t.Errorf("got %q, want %q", fsm["em0"], "LAN")
	}
	if fsm["em1"] != "IOT" {
		t.Errorf("got %q, want %q", fsm["em1"], "IOT")
	}
}

func TestFlexStringMap_EmptyArray(t *testing.T) {
	var fsm flexStringMap
	if err := json.Unmarshal([]byte(`[]`), &fsm); err != nil {
		t.Fatalf("unexpected error for empty array: %v", err)
	}
	if fsm == nil {
		t.Error("expected non-nil map, got nil")
	}
	if len(fsm) != 0 {
		t.Errorf("expected empty map, got %v", fsm)
	}
}

func TestFlexStringMap_Null(t *testing.T) {
	var fsm flexStringMap
	if err := json.Unmarshal([]byte(`null`), &fsm); err != nil {
		t.Fatalf("unexpected error for null: %v", err)
	}
	if len(fsm) != 0 {
		t.Errorf("expected empty map, got %v", fsm)
	}
}

func TestFlexStringMap_EmptyObject(t *testing.T) {
	var fsm flexStringMap
	if err := json.Unmarshal([]byte(`{}`), &fsm); err != nil {
		t.Fatalf("unexpected error for empty object: %v", err)
	}
	if len(fsm) != 0 {
		t.Errorf("expected empty map, got %v", fsm)
	}
}

func TestFlexInt_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want int
	}{
		{"number", `12345`, 12345},
		{"quoted number", `"12345"`, 12345},
		{"float number", `1750000000.0`, 1750000000},
		{"null", `null`, 0},
		{"empty string", `""`, 0},
		{"empty array", `[]`, 0},
		{"garbage string", `"never"`, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var f flexInt
			if err := json.Unmarshal([]byte(tt.in), &f); err != nil {
				t.Fatalf("flexInt must never fail on OPNsense shapes, got error: %v", err)
			}
			if f.Int() != tt.want {
				t.Errorf("flexInt(%s) = %d, want %d", tt.in, f.Int(), tt.want)
			}
		})
	}
}

func TestFlexBool_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"non-empty array (live reserved)", `["hwaddr"]`, true},
		{"empty array (live dynamic)", `[]`, false},
		{"legacy string 1", `"1"`, true},
		{"legacy string 0", `"0"`, false},
		{"empty string", `""`, false},
		{"null", `null`, false},
		{"json true", `true`, true},
		{"json false", `false`, false},
		{"number 1", `1`, true},
		{"number 0", `0`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var fb flexBool
			if err := json.Unmarshal([]byte(tt.input), &fb); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if fb.Bool() != tt.want {
				t.Errorf("flexBool(%s) = %v, want %v", tt.input, fb.Bool(), tt.want)
			}
		})
	}
}
