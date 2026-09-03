package opnsense

import (
	"encoding/json"
	"math"
	"sort"
	"strings"
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
	// PwdChangedAt is when this account's password was last changed (#583).
	// Upstream writes it as `microtime(true)` — Auth/Api/UserController.php:104
	// on an API/GUI change and etc/inc/auth.inc:461 on the legacy path — into a
	// TextField (Auth/User.xml:35). So the wire value is a STRING holding float
	// UNIX SECONDS with a microsecond fraction: seconds, NOT milliseconds, and
	// not a formatted date like the sibling `expires` field a few lines up.
	//
	// CONDITIONAL: written only when a password is actually changed, so it is
	// an empty string on any account whose password predates the feature.
	// Upstream reads it back behind `empty(...) ? 0 : ...` (Auth/Local.php:124),
	// i.e. it treats "never recorded" as its own case, and so do we.
	//
	// This is still aggregate-only data: the value is folded into a
	// whole-population maximum and the row's name is never bound.
	PwdChangedAt flexString `json:"pwd_changed_at"`
	// ShellWarning is upstream's own computed warning flag, not raw config.
	// UserController.php:121 sets it on every search row as
	//   strpos($row['shell'], '/') === 0 && empty($row['is_admin']) ? '1' : '0'
	// so it means "a NON-ADMIN account has been given a real login shell" — it
	// says nothing about WHICH shell, and an administrator with /bin/sh does
	// NOT raise it. Always present, always the string "1" or "0".
	ShellWarning flexString `json:"shell_warning"`
}

type authUserSearchResponse struct {
	Rows []authUserRow `json:"rows"`
}

// authAPIKeySearchResponse mirrors api/auth/user/search_api_key for the
// aggregate metrics path. Rows remain empty structs so usernames and key
// material never enter that collector's decoded value.
type authAPIKeySearchResponse struct {
	Rows []struct{} `json:"rows"`
}

// authAPIKeyOwnerSearchResponse is used only by the separately opt-in posture
// snapshot. It retains username and deliberately excludes key and id, leaving
// credential material outside the decoded value.
type authAPIKeyOwnerSearchResponse struct {
	Rows []authAPIKeyOwnerRow `json:"rows"`
}

type authAPIKeyOwnerRow struct {
	Username string `json:"username"`
}

func (r *authAPIKeyOwnerRow) UnmarshalJSON(data []byte) error {
	var wire struct {
		Username string `json:"username"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	r.Username = wire.Username
	return nil
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
	// UsersWithShellWarning counts accounts upstream itself flags in the GUI:
	// a non-admin user with a real login shell (#583).
	UsersWithShellWarning int
	// OldestPasswordAgeSeconds is the age of the LEAST recently changed
	// password across all accounts that have a recorded change time.
	// HasOldestPasswordAge is false when no account has one at all — the
	// aggregate is then absent rather than 0, because 0 would read as "every
	// password was just changed", the exact inverse of the truth.
	OldestPasswordAgeSeconds float64
	HasOldestPasswordAge     bool
	// UsersWithUnknownPasswordAge counts accounts with no usable change time
	// (empty, absent, or unparseable). These are NOT folded into the maximum
	// above: an account whose password has never been changed is the worst
	// posture on the box, and quietly dropping it would make the age gauge read
	// healthier than reality. The two series have to be read together.
	UsersWithUnknownPasswordAge int
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
		if row.ShellWarning.String() == "1" {
			data.UsersWithShellWarning++
		}
		if changed, ok := parseAuthPwdChangedAt(row.PwdChangedAt.String()); ok {
			// A clock skew or a hand-edited config can put the recorded change
			// in the future; clamp at zero rather than reporting a negative
			// age, which would silently satisfy every "older than N" alert.
			age := now.Sub(changed).Seconds()
			if age < 0 {
				age = 0
			}
			if !data.HasOldestPasswordAge || age > data.OldestPasswordAgeSeconds {
				data.OldestPasswordAgeSeconds = age
				data.HasOldestPasswordAge = true
			}
		} else {
			data.UsersWithUnknownPasswordAge++
		}
	}
	return data, nil
}

// parseAuthPwdChangedAt converts an Auth/User "pwd_changed_at" value — PHP
// microtime(true), i.e. float Unix SECONDS with a microsecond fraction, stored
// as text — into a time. Returns ok=false for an empty value (the password has
// never been changed since OPNsense started recording it) or an unparseable
// one; callers must count those separately rather than treating them as
// "changed at epoch 0", which would report a 56-year-old password.
func parseAuthPwdChangedAt(raw string) (time.Time, bool) {
	secs, ok := safeParseFloatOK(strings.TrimSpace(raw))
	if !ok || secs <= 0 {
		return time.Time{}, false
	}
	whole, frac := math.Modf(secs)
	return time.Unix(int64(whole), int64(frac*1e9)), true
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

// APIKeyOwner is one local account with one or more configured API keys. It
// deliberately carries only the owner and aggregate count: neither API-key
// half nor its id is useful for posture drift and neither is safe to ship.
type APIKeyOwner struct {
	Owner string
	Count int
}

// FetchAuthAPIKeyOwners returns a stable aggregate of configured API keys by
// local owner. The upstream endpoint is core, GET and config-driven; callers
// that need only the total should continue to use FetchAuthAPIKeyCount.
func (c *Client) FetchAuthAPIKeyOwners() ([]APIKeyOwner, *APICallError) {
	var resp authAPIKeyOwnerSearchResponse

	url, ok := c.endpoints["authAPIKeys"]
	if !ok {
		return nil, &APICallError{
			Endpoint:   "authAPIKeys",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return nil, err
	}

	counts := make(map[string]int, len(resp.Rows))
	for _, row := range resp.Rows {
		counts[row.Username]++
	}
	owners := make([]APIKeyOwner, 0, len(counts))
	for owner, count := range counts {
		owners = append(owners, APIKeyOwner{Owner: owner, Count: count})
	}
	sort.Slice(owners, func(i, j int) bool { return owners[i].Owner < owners[j].Owner })
	return owners, nil
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
