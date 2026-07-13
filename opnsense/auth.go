package opnsense

import (
	"encoding/json"
	"time"
)

// authExpiresLayout is the date format OPNsense's Auth/User model uses for the
// "expires" field: a literal m/d/Y string (e.g. "01/01/2020"), never epoch
// seconds. An empty string means "never expires", not "expired at epoch 0"
// (verified against a live OPNsense 26.7-devel box, #222).
const authExpiresLayout = "01/02/2006"

// otpSeedPresence decodes a JSON field into whether it was a non-empty string,
// discarding the value itself. This is the narrowest possible reading of a
// TOTP seed: the seed characters exist only inside the local `s` variable of
// UnmarshalJSON below, for the duration of that single call, and are never
// assigned to any field that outlives it — so the secret never enters exporter
// memory as a named struct field, let alone a metric label or log line
// (#222 CRITICAL sensitivity rule).
//
// Also tolerates the OPNsense PHP empty-array quirk (see flexString): some
// generations serialize an absent field as [] rather than "". A non-empty
// array is not a documented otp_seed shape; treating it the same as an empty
// array is the safe reading — it never risks capturing the value.
type otpSeedPresence bool

// UnmarshalJSON implements json.Unmarshaler.
func (p *otpSeedPresence) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		*p = false
		return nil
	}
	if data[0] == '[' {
		*p = false
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	*p = otpSeedPresence(s != "")
	return nil
}

// authUserRow mirrors api/auth/user/search bootgrid rows — narrowly. The real
// payload also carries password (bcrypt hash), scrambled_password,
// authorizedkeys (SSH public keys), apikeys (API key material + salted
// hashes), priv/%priv, group_memberships, descr, email, comment, and more —
// none of that is modeled here, on purpose: this collector emits aggregate
// security-posture counts only, never per-user detail, so there is nothing to
// gain from decoding fields the exporter will never expose. Go's
// json.Unmarshal silently ignores object keys with no matching struct field,
// so those fields never touch exporter memory beyond the raw response buffer.
type authUserRow struct {
	Disabled flexString      `json:"disabled"`
	IsAdmin  flexString      `json:"is_admin"`
	Expires  flexString      `json:"expires"`
	HasOTP   otpSeedPresence `json:"otp_seed"`
}

type authUserSearchResponse struct {
	Rows []authUserRow `json:"rows"`
}

// authAPIKeySearchResponse mirrors api/auth/user/search_api_key — deliberately
// as narrowly as possible. Each real row carries "username", "key" (the public
// half of an API key/secret pair) and "id"; none of it is needed for an
// aggregate count, so rows are decoded as bare struct{} — json.Unmarshal counts
// the array elements without ever binding a single field out of any row, which
// means the key material and usernames never reach a Go struct field at all.
type authAPIKeySearchResponse struct {
	Rows []struct{} `json:"rows"`
}

// authGroupSearchResponse mirrors api/auth/group/search. Only the row count is
// needed, so rows are decoded as bare struct{} for the same reason as the API
// key response above (a group's member list is not aggregate-count material,
// so it is never modeled).
type authGroupSearchResponse struct {
	Rows []struct{} `json:"rows"`
}

// AuthPosture holds aggregate local-authentication security-posture counts
// (#222): how many local users/groups/API keys exist, how many users are
// disabled vs enabled, admins, expired accounts, and accounts with a TOTP seed
// configured. Every field is a whole-population aggregate — never a
// per-user/per-key/per-group breakdown, since usernames and group names carry
// PII/cardinality risk that a homelab-scale local auth store gains nothing
// from exposing as label values.
type AuthPosture struct {
	UsersTotal    int
	UsersEnabled  int
	UsersDisabled int
	AdminUsers    int
	ExpiredUsers  int
	UsersWithOTP  int
}

// FetchAuthUsers returns aggregate local-user security-posture counts from
// api/auth/user/search. All-GET, wholly config-driven data — a good
// response-cache candidate (see --exporter.cache-ttl).
func (c *Client) FetchAuthUsers() (AuthPosture, *APICallError) {
	var resp authUserSearchResponse
	var data AuthPosture

	url, ok := c.endpoints["authUsers"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "authUsers",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return data, err
	}

	now := time.Now()
	data.UsersTotal = len(resp.Rows)
	for _, row := range resp.Rows {
		if row.Disabled.String() == "1" {
			data.UsersDisabled++
		} else {
			data.UsersEnabled++
		}
		if row.IsAdmin.String() == "1" {
			data.AdminUsers++
		}
		if row.HasOTP {
			data.UsersWithOTP++
		}
		if authUserExpired(row.Expires.String(), now) {
			data.ExpiredUsers++
		}
	}
	return data, nil
}

// authUserExpired reports whether an Auth/User "expires" value (an m/d/Y date
// string, or "" for never-expires) is in the past relative to now. An
// unparseable value is treated as not-expired rather than guessed at — payload
// drift on this field is a "chase" candidate, not a reason to false-fire an
// expiry count.
func authUserExpired(expires string, now time.Time) bool {
	if expires == "" {
		return false
	}
	t, err := time.Parse(authExpiresLayout, expires)
	if err != nil {
		return false
	}
	return now.After(t)
}

// FetchAuthAPIKeyCount returns the total number of local-user API keys
// configured, from api/auth/user/search_api_key. GET, wholly config-driven —
// a good response-cache candidate.
func (c *Client) FetchAuthAPIKeyCount() (int, *APICallError) {
	var resp authAPIKeySearchResponse

	url, ok := c.endpoints["authAPIKeys"]
	if !ok {
		return 0, &APICallError{
			Endpoint:   "authAPIKeys",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return 0, err
	}
	return len(resp.Rows), nil
}

// FetchAuthGroupCount returns the total number of local auth groups
// configured, from api/auth/group/search. GET, wholly config-driven — a good
// response-cache candidate.
func (c *Client) FetchAuthGroupCount() (int, *APICallError) {
	var resp authGroupSearchResponse

	url, ok := c.endpoints["authGroups"]
	if !ok {
		return 0, &APICallError{
			Endpoint:   "authGroups",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return 0, err
	}
	return len(resp.Rows), nil
}
