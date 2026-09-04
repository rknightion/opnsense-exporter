package opnsense

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// ConfigSnapshotEntity is a current, upstream-produced configuration row
// projected from the firewall search endpoints. Config never includes a field
// whose name marks it as a credential or private key.
type ConfigSnapshotEntity struct {
	Kind   string
	ID     string
	Config map[string]any
}

type configSnapshotSearchResponse struct {
	Rows []json.RawMessage `json:"rows"`
}

// FetchFirewallConfigSnapshots returns the current filter and four NAT rule
// sets. It intentionally reuses the already-registered search endpoints: no
// endpoint registry or schema-contract expansion is required. The row bodies
// are preserved as JSON objects so this config snapshot follows fields OPNsense
// actually produced rather than a guessed local struct.
func (c *Client) FetchFirewallConfigSnapshots() ([]ConfigSnapshotEntity, *APICallError) {
	type endpoint struct {
		kind   string
		name   EndpointName
		method string
		body   string
	}
	endpoints := []endpoint{
		{kind: "filter_rule", name: "firewallRules", method: "POST", body: fetchFirewallRulesPayload},
		{kind: "source_nat", name: "natSourceNATRules", method: "GET"},
		{kind: "d_nat", name: "natDNATRules", method: "GET"},
		{kind: "one_to_one", name: "natOneToOneRules", method: "GET"},
		{kind: "npt", name: "natNPTRules", method: "GET"},
	}

	var entities []ConfigSnapshotEntity
	for _, endpoint := range endpoints {
		path, ok := c.endpoints[endpoint.name]
		if !ok {
			return nil, &APICallError{Endpoint: string(endpoint.name), Message: "endpoint not found in client endpoints"}
		}
		var response configSnapshotSearchResponse
		var body io.Reader
		if endpoint.body != "" {
			body = strings.NewReader(endpoint.body)
		}
		if err := c.do(endpoint.method, path, body, &response); err != nil {
			return nil, err
		}
		rows, err := configSnapshotRows(endpoint.kind, response.Rows)
		if err != nil {
			return nil, &APICallError{Endpoint: string(endpoint.name), Message: err.Error()}
		}
		entities = append(entities, rows...)
	}
	return entities, nil
}

func configSnapshotRows(kind string, rows []json.RawMessage) ([]ConfigSnapshotEntity, error) {
	entities := make([]ConfigSnapshotEntity, 0, len(rows))
	for _, row := range rows {
		decoder := json.NewDecoder(bytes.NewReader(row))
		decoder.UseNumber()
		var config map[string]any
		if err := decoder.Decode(&config); err != nil {
			return nil, fmt.Errorf("decode %s configuration row: %w", kind, err)
		}
		id, ok := config["uuid"].(string)
		if !ok || strings.TrimSpace(id) == "" {
			return nil, fmt.Errorf("%s configuration row has no uuid", kind)
		}
		redactConfigSnapshotFields(config)
		entities = append(entities, ConfigSnapshotEntity{Kind: kind, ID: id, Config: config})
	}
	return entities, nil
}

func redactConfigSnapshotFields(value any) {
	switch value := value.(type) {
	case map[string]any:
		for key, child := range value {
			if SensitiveConfigKey(key) {
				delete(value, key)
				continue
			}
			redactConfigSnapshotFields(child)
		}
	case []any:
		for _, child := range value {
			redactConfigSnapshotFields(child)
		}
	}
}

// sensitiveConfigSubstrings, sensitiveConfigTerms and sensitiveConfigExact are
// the shared vocabulary for every path that ships firewall configuration off the
// box: JSON snapshot rows, config.xml revision diffs and API error bodies.
// Keeping one vocabulary is the point — when the paths drifted, a field could
// be redacted in one and shipped in another.
//
// Substring matching is deliberate: it catches wgPrivateKey, radius_secret and
// api-key alike. The exact set carries OPNsense element names too short to
// match safely as a substring — <prv> is the private half of a certificate and
// <psk> is an IPsec pre-shared key.
var (
	sensitiveConfigSubstrings = []string{
		"password", "passphrase", "secret", "privatekey", "privkey",
		"sharedkey", "token", "apikey", "authkey", "credential", "passwd",
	}
	// A term is deliberately narrower than a substring. prv is the private
	// certificate half, and appears in compound keys such as prv_payload, but
	// it is too short to match at an arbitrary position.
	sensitiveConfigTerms = map[string]struct{}{
		"prv": {},
	}
	sensitiveConfigExact = map[string]struct{}{
		"psk": {}, "pass": {},
		"otpseed": {}, "ldapbindpw": {}, "enckey": {}, "community": {},
	}
	sensitiveConfigNormalizer = strings.NewReplacer("_", "", "-", "", ".", "", "%", "")
)

// SensitiveConfigKey reports whether a configuration key or XML element name
// names a credential that must never leave the firewall in a log record.
//
// The comparison is made on a separator-free lowercase form so snake_case,
// kebab-case, dotted and camelCase wire keys all resolve to the same
// vocabulary. Over-matching here is cheap; under-matching ships a credential.
func SensitiveConfigKey(key string) bool {
	normalized := strings.ToLower(sensitiveConfigNormalizer.Replace(key))
	if _, ok := sensitiveConfigExact[normalized]; ok {
		return true
	}
	for _, needle := range sensitiveConfigSubstrings {
		if strings.Contains(normalized, needle) {
			return true
		}
	}
	if strings.HasPrefix(normalized, "prv") {
		return true
	}
	for _, term := range strings.FieldsFunc(strings.ToLower(key), func(r rune) bool {
		return r == '_' || r == '-' || r == '.' || r == '%'
	}) {
		if _, ok := sensitiveConfigTerms[term]; ok {
			return true
		}
	}
	return false
}
