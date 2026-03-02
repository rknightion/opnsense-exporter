package opnsense

import (
	"reflect"
	"regexp"
	"testing"

	"github.com/prometheus/common/promslog"
)

func TestParsePercentage(t *testing.T) {
	logger := promslog.NewNopLogger()
	testRegex := regexp.MustCompile(`\d\.\d %`)

	tests := []struct {
		name           string
		value          string
		regex          *regexp.Regexp
		replacePattern string
		valueTypeName  string
		gatewayName    string
		expected       float64
	}{
		{
			name:           "Valid percentage with space",
			value:          "50.5 %",
			regex:          testRegex,
			replacePattern: " %",
			valueTypeName:  "loss",
			gatewayName:    "Gateway1",
			expected:       50.5,
		},
		{
			name:           "Valid percentage with space",
			value:          "5.5 %",
			regex:          testRegex,
			replacePattern: " %",
			valueTypeName:  "loss",
			gatewayName:    "Gateway1",
			expected:       5.5,
		},
		{
			name:           "Invalid percentage format",
			value:          "invalid %",
			regex:          testRegex,
			replacePattern: " %",
			valueTypeName:  "loss",
			gatewayName:    "Gateway1",
			expected:       -1.0,
		},
		{
			name:           "Invalid regex match (no space)",
			value:          "50.5%",
			regex:          testRegex,
			replacePattern: " %",
			valueTypeName:  "loss",
			gatewayName:    "Gateway1",
			expected:       -1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := parseStringToFloatWithReplace(tc.value, tc.regex, tc.replacePattern, tc.valueTypeName, logger)
			if result != tc.expected {
				t.Errorf("parsePercentage(%s, %v, %s, %s, logger, %s) = %v; want %v",
					tc.value, tc.regex, tc.replacePattern, tc.valueTypeName, tc.gatewayName, result, tc.expected)
			}
		})
	}
}

func TestSliceIntToMapStringInt(t *testing.T) {
	input := []string{"1", "2", "3"}
	expected := map[string]int{"1": 1, "2": 2, "3": 3}

	result, _ := sliceIntToMapStringInt(input, "test")

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}

func TestSliceIntToMapStringInt_Error(t *testing.T) {
	input := []string{"1", "abc", "3"}

	_, err := sliceIntToMapStringInt(input, "test")
	if err == nil {
		t.Error("expected error for non-numeric input, got nil")
	}
}

func TestParseStringToInt(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		expected  int
		wantError bool
	}{
		{"Valid integer", "123", 123, false},
		{"Zero", "0", 0, false},
		{"Negative", "-5", -5, false},
		{"Invalid string", "abc", 0, true},
		{"Empty string", "", 0, true},
		{"Float string", "3.14", 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := parseStringToInt(tc.value, "test-endpoint")
			if tc.wantError && err == nil {
				t.Errorf("parseStringToInt(%q) expected error, got nil", tc.value)
			}
			if !tc.wantError && err != nil {
				t.Errorf("parseStringToInt(%q) unexpected error: %v", tc.value, err)
			}
			if result != tc.expected {
				t.Errorf("parseStringToInt(%q) = %d; want %d", tc.value, result, tc.expected)
			}
		})
	}
}

func TestSafeAtoi(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected int
	}{
		{"Valid", "42", 42},
		{"Zero", "0", 0},
		{"Empty", "", 0},
		{"Invalid", "abc", 0},
		{"Negative", "-10", -10},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := safeAtoi(tc.value)
			if result != tc.expected {
				t.Errorf("safeAtoi(%q) = %d; want %d", tc.value, result, tc.expected)
			}
		})
	}
}

func TestSafeParseFloat(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected float64
	}{
		{"Valid", "3.14", 3.14},
		{"Zero", "0", 0},
		{"Empty", "", 0},
		{"Invalid", "abc", 0},
		{"Negative", "-1.5", -1.5},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := safeParseFloat(tc.value)
			if result != tc.expected {
				t.Errorf("safeParseFloat(%q) = %f; want %f", tc.value, result, tc.expected)
			}
		})
	}
}

func TestParseBoolToInt(t *testing.T) {
	if parseBoolToInt(true) != 1 {
		t.Error("parseBoolToInt(true) should be 1")
	}
	if parseBoolToInt(false) != 0 {
		t.Error("parseBoolToInt(false) should be 0")
	}
}

func TestParseOpenVPNsessionStatusToInt(t *testing.T) {
	tests := []struct {
		name     string
		status   string
		expected int
	}{
		{"OK", "ok", 1},
		{"Empty", "", 0},
		{"Other", "disconnected", 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := parseOpenVPNsessionStatusToInt(tc.status)
			if result != tc.expected {
				t.Errorf("parseOpenVPNsessionStatusToInt(%q) = %d; want %d", tc.status, result, tc.expected)
			}
		})
	}
}

func TestParseLineRateBits(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected int
	}{
		{"Valid with suffix", "1000 bit/s", 1000},
		{"With extra spaces", " 500 bit/s ", 500},
		{"No suffix", "2000", 2000},
		{"Empty", "", 0},
		{"Garbage", "garbage", 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := parseLineRateBits(tc.value)
			if result != tc.expected {
				t.Errorf("parseLineRateBits(%q) = %d; want %d", tc.value, result, tc.expected)
			}
		})
	}
}

func TestParseStringToBool(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected bool
	}{
		{
			name:     "Zero",
			value:    "0",
			expected: false,
		},
		{
			name:     "One",
			value:    "1",
			expected: true,
		},
		{
			name:     "Invalid/Unknown",
			value:    "2",
			expected: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := parseStringToBool(tc.value)
			if result != tc.expected {
				t.Errorf("parseStringToBool(%s) = %v; want %v",
					tc.value, result, tc.expected)
			}
		})
	}
}
