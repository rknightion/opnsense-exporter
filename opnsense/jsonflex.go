package opnsense

import (
	"encoding/json"
	"fmt"
	"strings"
)

// flexString is a string type whose JSON unmarshaling tolerates the OPNsense
// PHP API quirk where an empty or absent value is serialized as a JSON array
// ([]) rather than a quoted string ("").  Any array input (empty or not) is
// decoded as an empty string "".  JSON strings are kept as-is; JSON numbers
// and booleans are converted to their literal text representation; null decodes
// to "".
type flexString string

// String returns the underlying string value.
func (f flexString) String() string {
	return string(f)
}

// UnmarshalJSON implements json.Unmarshaler.
func (f *flexString) UnmarshalJSON(data []byte) error {
	// Null → empty string.
	if string(data) == "null" {
		*f = ""
		return nil
	}

	// Array ([] or any JSON array) → empty string.
	if len(data) > 0 && data[0] == '[' {
		*f = ""
		return nil
	}

	// Number or bool: store literal text.
	if len(data) > 0 && data[0] != '"' {
		*f = flexString(data)
		return nil
	}

	// Normal JSON string.
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("flexString: %w", err)
	}
	*f = flexString(s)
	return nil
}

// flexBool is a bool type whose JSON unmarshaling tolerates the several shapes
// OPNsense PHP APIs use for a boolean-ish field. In particular the modern lease
// APIs encode "is_reserved" as a JSON array: a NON-EMPTY array (e.g.
// ["hwaddr"]) means true, an empty array ([]) means false. Older releases used
// the string "1"/"0". This type maps:
//   - non-empty array            -> true
//   - empty array, null          -> false
//   - JSON true                  -> true
//   - string/number "1","2",...  -> true (any non-empty, non-"0", non-"false")
//   - string "", "0", "false"    -> false
type flexBool bool

// Bool returns the underlying bool value.
func (f flexBool) Bool() bool { return bool(f) }

// UnmarshalJSON implements json.Unmarshaler.
func (f *flexBool) UnmarshalJSON(data []byte) error {
	s := strings.TrimSpace(string(data))
	switch {
	case s == "null", s == "[]", s == "false", s == `""`, s == `"0"`, s == "0":
		*f = false
	case len(s) > 0 && s[0] == '[': // non-empty array -> reserved
		*f = true
	default:
		// JSON true, any non-zero number, or a non-empty string like "1".
		*f = true
	}
	return nil
}

// flexStringMap is a map[string]string type whose JSON unmarshaling tolerates
// the OPNsense PHP API quirk where an empty map is serialized as a JSON array
// ([]) rather than an object ({}).  Any array input is decoded as an empty map.
// Null is also decoded as an empty (non-nil) map.
type flexStringMap map[string]string

// UnmarshalJSON implements json.Unmarshaler.
func (f *flexStringMap) UnmarshalJSON(data []byte) error {
	// Null → empty map.
	if string(data) == "null" {
		*f = make(flexStringMap)
		return nil
	}

	// Array ([] or any JSON array) → empty map.
	if len(data) > 0 && data[0] == '[' {
		*f = make(flexStringMap)
		return nil
	}

	// Normal JSON object.
	m := make(map[string]string)
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("flexStringMap: %w", err)
	}
	*f = m
	return nil
}
