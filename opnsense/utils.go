package opnsense

import (
	"fmt"
	"log/slog"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// parseStringToInt parses a string value to an int64 value.
// int64 (not int) so that large counters — e.g. interface byte counters or
// SMART raw values — parse correctly on 32-bit architectures too.
// The endpoint is used to identify the EndpointPath that the caller used.
// so we can propagate in the *APICallError.
func parseStringToInt(value string, endpoint EndpointPath) (int64, *APICallError) {
	intValue, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, &APICallError{
			Endpoint:   string(endpoint),
			Message:    fmt.Sprintf("error parsing '%s' to int: %s", value, err.Error()),
			StatusCode: 0,
		}
	}
	return intValue, nil
}

// parseStringToFloatWithReplace parses a string value to a float64 value.
// The replace pattern is used to remove any characters that are not part of the float64 value.
// The regex is first used to check if the value matches the regex format.
func parseStringToFloatWithReplace(value string, regex *regexp.Regexp, replacePattern string, valueTypeName string, logger *slog.Logger) float64 {
	if regex.MatchString(value) {
		cleanValue := strings.ReplaceAll(value, replacePattern, "")
		parsedValue, err := strconv.ParseFloat(cleanValue, 64)
		if err != nil {
			logger.Warn(
				fmt.Sprintf("parsing %s: '%s' to float64 failed", valueTypeName, value),
				"details", err,
			)
			return -1.0
		}
		return parsedValue
	}

	logger.Warn(
		fmt.Sprintf("parsing %s: '%s' to float64 failed. Pattern matching failed.", valueTypeName, value),
	)
	return -1.0
}

// sliceIntToMapStringInt is a helper function to convert a slice of strings to a map of string:int64
// The key of the map is the string value in the slice and
// the value of the map is the int64 value of the string.
// The endpoint is used to identify the EndpointPath that the caller used.
// so we can propagate in the *APICallError.
// Fails if any of the string values in the slice cannot be parsed to an int64.
func sliceIntToMapStringInt(strings []string, url EndpointPath) (map[string]int64, *APICallError) {
	ints := make(map[string]int64)

	for _, str := range strings {
		value, err := parseStringToInt(str, url)
		if err != nil {
			return nil, err
		}
		ints[str] = value
	}

	return ints, nil
}

// parseStringToBool parses a string value to a bool value.
// The value is considered true if it is not "0".
func parseStringToBool(value string) bool {
	return value != "0"
}

func parseBoolToInt(b bool) int {
	var i int
	if b {
		i = 1
	} else {
		i = 0
	}
	return i
}

// parseOpenVPNsessionStatusToInt maps an OPNsense OpenVPN session status string
// to 1 (up) or 0 (down). The status comes from ovpn_status.py: server instances
// with connected clients report "ok" (from the status header), while client and
// point-to-point instances report the lowercased OpenVPN state-machine value —
// "connected" when fully established. Transitional states (wait/auth/
// reconnecting/...), "failed", and an absent status are treated as not-up.
func parseOpenVPNsessionStatusToInt(status string) int {
	switch status {
	case "ok", "connected":
		return 1
	default:
		return 0
	}
}

// safeAtoi parses a string to int64, returning 0 on any error — including
// out-of-range values. int64 (not int) so large counters (10 Gbit line
// rates, cumulative DNS counters) survive 32-bit source builds.
// Useful for OPNsense API fields that may be empty or missing.
func safeAtoi(s string) int64 {
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return v
}

// safeParseFloat parses a string to float64, returning 0 on any error —
// including out-of-range values, where strconv would otherwise hand back ±Inf.
// Useful for OPNsense API fields that may be empty or missing.
//
// Non-finite results are rejected as if they had failed to parse (#323).
// strconv.ParseFloat accepts the literals "NaN", "Inf" and "Infinity" (any
// case, optionally signed) and returns them with a NIL error, so without this
// guard they sail straight through into metric values. That is not a harmless
// odd number: every comparison against NaN is false, so a NaN seed in a
// max()-style scan (opnsense/backup.go, opnsense/snapshots.go) can never be
// displaced, and the resulting NaN gauge makes a `time() - metric > X`
// staleness alert silently never fire. +Inf is the mirror image — it wins
// every comparison and pins the gauge at infinity. Every caller already
// treats 0 (or ok=false) as "absent", so folding non-finite into that path
// fixes all of them at once.
func safeParseFloat(s string) float64 {
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
		return 0
	}
	return v
}

// safeParseFloatOK is like safeParseFloat but also reports whether the parse
// succeeded, so callers can distinguish an absent/empty field from a genuine 0
// (e.g. a pending-CSR certificate with no valid_from/valid_to vs. epoch 0).
//
// This is the more consequential half of the non-finite guard described on
// safeParseFloat: opnsense/certificates.go uses the ok flag specifically to
// decide whether to emit cert_valid_to_seconds / ca_valid_to_seconds at all,
// so a NaN reported as ok=true is published as a NaN gauge and defeats every
// certificate-expiry alert built on it.
func safeParseFloatOK(s string) (float64, bool) {
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
		return 0, false
	}
	return v, true
}

// parseLineRateBits strips the "bit/s" suffix from OPNsense line rate strings
// and returns the numeric value as an int64 (10 Gbit rates exceed int32).
func parseLineRateBits(v string) int64 {
	v = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(v), "bit/s"))
	return safeAtoi(v)
}
