// Command configredactionverify checks delivered configuration bodies without
// rendering their contents. It is for the live-delivery proof only; it must
// never sit in the export path before data reaches the configured sink.
package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

const redactionMarker = "[redacted]"

type request struct {
	ConfigChange []string `json:"configchange"`
	ConfigState  []string `json:"configstate"`
}

// result is intentionally fixed-schema: it contains no body, key, value or
// decoder error that could disclose firewall configuration in a CI summary.
type result struct {
	ConfigChangeBodies            int  `json:"configchange_bodies"`
	ConfigChangeSensitiveElements int  `json:"configchange_sensitive_elements"`
	ConfigChangeBodiesRedacted    bool `json:"configchange_bodies_redacted"`
	ConfigStateBodies             int  `json:"configstate_bodies"`
	ConfigStateSensitiveKeys      int  `json:"configstate_sensitive_keys"`
	ConfigStateBodiesRedacted     bool `json:"configstate_bodies_redacted"`
}

func main() {
	var input request
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 8<<20))
	if decoder.Decode(&input) != nil {
		input = request{}
	}
	_, _ = os.Stdout.Write(mustJSON(verify(input)))
}

func mustJSON(value result) []byte {
	encoded, err := json.Marshal(value)
	if err != nil {
		return []byte(`{"configchange_bodies":0,"configchange_sensitive_elements":0,"configchange_bodies_redacted":false,"configstate_bodies":0,"configstate_sensitive_keys":0,"configstate_bodies_redacted":false}`)
	}
	return append(encoded, '\n')
}

func verify(input request) result {
	result := result{
		ConfigChangeBodies:         len(input.ConfigChange),
		ConfigChangeBodiesRedacted: len(input.ConfigChange) > 0,
		ConfigStateBodies:          len(input.ConfigState),
		ConfigStateBodiesRedacted:  len(input.ConfigState) > 0,
	}
	for _, body := range input.ConfigChange {
		clean, sensitive := verifyConfigChange(body)
		result.ConfigChangeSensitiveElements += sensitive
		result.ConfigChangeBodiesRedacted = result.ConfigChangeBodiesRedacted && clean
	}
	for _, body := range input.ConfigState {
		clean, sensitive := verifyConfigState(body)
		result.ConfigStateSensitiveKeys += sensitive
		result.ConfigStateBodiesRedacted = result.ConfigStateBodiesRedacted && clean
	}
	return result
}

// verifyConfigChange mirrors the redactor's diff-line discipline. Unified
// diffs are not XML documents, so a general XML decoder would reject valid
// input. Instead this scanner insists every sensitive element emitted on an
// added or removed line contains only the source's exact marker. It rejects
// malformed tags rather than treating an unscannable body as clean.
func verifyConfigChange(body string) (bool, int) {
	if strings.TrimSpace(body) == "" {
		return false, 0
	}
	seenXML := false
	openTag := ""
	var openPrefix byte
	sensitive := 0
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "@@") {
			openTag = ""
			continue
		}
		if strings.HasPrefix(line, "+++ ") || strings.HasPrefix(line, "--- ") ||
			strings.HasPrefix(line, "+++\t") || strings.HasPrefix(line, "---\t") {
			continue
		}
		prefix := byte(0)
		lineBody := line
		if len(line) > 0 && (line[0] == '+' || line[0] == '-' || line[0] == ' ') {
			prefix, lineBody = line[0], line[1:]
		}
		if openTag != "" && prefix != openPrefix {
			openTag = ""
		}
		clean, saw, nextOpen, count := verifyConfigChangeLine(lineBody, openTag)
		if !clean {
			return false, sensitive + count
		}
		seenXML = seenXML || saw
		sensitive += count
		openTag = nextOpen
		openPrefix = prefix
	}
	return seenXML, sensitive
}

func verifyConfigChangeLine(line, openTag string) (clean, sawXML bool, nextOpen string, sensitive int) {
	for cursor := 0; cursor < len(line); {
		if openTag != "" {
			closing := "</" + openTag + ">"
			end := strings.Index(line[cursor:], closing)
			if end < 0 {
				return line[cursor:] == redactionMarker, true, openTag, sensitive
			}
			if line[cursor:cursor+end] != redactionMarker {
				return false, true, openTag, sensitive
			}
			cursor += end + len(closing)
			openTag = ""
			continue
		}
		start := strings.IndexByte(line[cursor:], '<')
		if start < 0 {
			return true, sawXML, "", sensitive
		}
		cursor += start
		end := strings.IndexByte(line[cursor:], '>')
		if end < 0 {
			return false, true, "", sensitive
		}
		tag := line[cursor : cursor+end+1]
		cursor += end + 1
		sawXML = true
		name, opening := xmlOpeningName(tag)
		if !opening {
			continue
		}
		if opnsense.SensitiveConfigKey(name) {
			sensitive++
			openTag = name
		}
	}
	// The source leaves an opening tag at the end of a line intact and
	// redacts its value on following lines. No value was present to inspect.
	return true, sawXML, openTag, sensitive
}

func xmlOpeningName(tag string) (string, bool) {
	if len(tag) < 3 || tag[0] != '<' || tag[len(tag)-1] != '>' {
		return "", false
	}
	inner := strings.TrimSpace(tag[1 : len(tag)-1])
	if inner == "" || strings.HasPrefix(inner, "/") || strings.HasPrefix(inner, "!") ||
		strings.HasPrefix(inner, "?") || strings.HasSuffix(inner, "/") {
		return "", false
	}
	name := inner
	if cut := strings.IndexAny(name, " \t\r\n"); cut >= 0 {
		name = name[:cut]
	}
	if name == "" || strings.ContainsAny(name, "<>\"'") {
		return "", false
	}
	return name, true
}

func verifyConfigState(body string) (bool, int) {
	decoder := json.NewDecoder(strings.NewReader(body))
	decoder.UseNumber()
	first, err := decoder.Token()
	if err != nil || (first != json.Delim('{') && first != json.Delim('[')) {
		return false, 0
	}
	clean, sensitive, err := verifyConfigStateToken(decoder, first)
	if err != nil {
		return false, sensitive
	}
	if _, err := decoder.Token(); err != io.EOF {
		return false, sensitive
	}
	return clean, sensitive
}

// Inspect tokens instead of decoding into maps: a later duplicate key must
// never overwrite and hide an earlier credential-bearing subtree.
func verifyConfigStateToken(decoder *json.Decoder, token json.Token) (bool, int, error) {
	delim, compound := token.(json.Delim)
	if !compound {
		return true, 0, nil
	}
	if delim != '{' && delim != '[' {
		return false, 0, errors.New("invalid snapshot structure")
	}
	seen := make(map[string]bool)
	clean, sensitive := true, 0
	for decoder.More() {
		if delim == '{' {
			keyToken, err := decoder.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok || seen[key] {
				return false, sensitive, errors.New("invalid snapshot key")
			}
			seen[key] = true
			if opnsense.SensitiveConfigKey(key) {
				clean = false
				sensitive++
			}
		}
		child, err := decoder.Token()
		if err != nil {
			return false, sensitive, err
		}
		childClean, childSensitive, err := verifyConfigStateToken(decoder, child)
		sensitive += childSensitive
		if err != nil {
			return false, sensitive, err
		}
		clean = clean && childClean
	}
	closing, err := decoder.Token()
	if err != nil || (delim == '{' && closing != json.Delim('}')) || (delim == '[' && closing != json.Delim(']')) {
		return false, sensitive, errors.New("invalid snapshot structure")
	}
	return clean, sensitive, nil
}
