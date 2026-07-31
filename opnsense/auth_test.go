package opnsense

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestFetchAuthUsers_Success uses the real capture shape from the dev-box
// provisioning for #222: root (admin, no expiry, no OTP), ci-canary (admin,
// no expiry, no OTP), testexpireduser (admin via group membership, expired
// 01/01/2020, OTP seed populated).
func TestFetchAuthUsers_Success(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{"rows":[
			{"uuid":"13cd06c7","uid":"0","name":"root","disabled":"0","scope":"system","expires":"","otp_seed":"","password":"$2y$11$hash","is_admin":"1"},
			{"uuid":"3d11e78e","uid":"2000","name":"ci-canary","disabled":"0","scope":"user","expires":"","otp_seed":"","password":"$2y$11$hash2","is_admin":"1"},
			{"uuid":"f4c17107","uid":"2001","name":"testexpireduser","disabled":"0","scope":"user","expires":"01/01/2020","otp_seed":"RGXQFIXS7BT5PRCVKWHWJ5T3Q4ZQXHJB","password":"$2y$11$hash3","is_admin":"1"}
		],"rowCount":3,"total":3,"current":1}`))
	})
	defer server.Close()

	data, err := client.FetchAuthUsers()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if data.UsersTotal != 3 {
		t.Errorf("expected UsersTotal=3, got %d", data.UsersTotal)
	}
	if data.UsersEnabled != 3 {
		t.Errorf("expected UsersEnabled=3, got %d", data.UsersEnabled)
	}
	if data.UsersDisabled != 0 {
		t.Errorf("expected UsersDisabled=0, got %d", data.UsersDisabled)
	}
	if data.AdminUsers != 3 {
		t.Errorf("expected AdminUsers=3, got %d", data.AdminUsers)
	}
	if data.ExpiredUsers != 1 {
		t.Errorf("expected ExpiredUsers=1, got %d", data.ExpiredUsers)
	}
	if data.UsersWithOTP != 1 {
		t.Errorf("expected UsersWithOTP=1, got %d", data.UsersWithOTP)
	}
}

func TestFetchAuthUsers_DisabledAndNonAdmin(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[
			{"disabled":"1","is_admin":"0","expires":"","otp_seed":""},
			{"disabled":"0","is_admin":"0","expires":"","otp_seed":""}
		]}`))
	})
	defer server.Close()

	data, err := client.FetchAuthUsers()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.UsersTotal != 2 {
		t.Errorf("expected UsersTotal=2, got %d", data.UsersTotal)
	}
	if data.UsersDisabled != 1 {
		t.Errorf("expected UsersDisabled=1, got %d", data.UsersDisabled)
	}
	if data.UsersEnabled != 1 {
		t.Errorf("expected UsersEnabled=1, got %d", data.UsersEnabled)
	}
	if data.AdminUsers != 0 {
		t.Errorf("expected AdminUsers=0, got %d", data.AdminUsers)
	}
}

// TestFetchAuthUsers_FutureExpiryNotExpired proves a future expires date does
// not count as expired.
func TestFetchAuthUsers_FutureExpiryNotExpired(t *testing.T) {
	future := time.Now().Add(24 * 365 * time.Hour).Format(authExpiresLayout)
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[{"disabled":"0","is_admin":"0","expires":"` + future + `","otp_seed":""}]}`))
	})
	defer server.Close()

	data, err := client.FetchAuthUsers()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.ExpiredUsers != 0 {
		t.Errorf("expected ExpiredUsers=0 for a future expiry, got %d", data.ExpiredUsers)
	}
}

// TestFetchAuthUsers_UnparseableExpiryNotCountedExpired covers a drifted/
// unexpected expires shape: never guess "expired" from something we can't
// parse.
func TestFetchAuthUsers_UnparseableExpiryNotCountedExpired(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[{"disabled":"0","is_admin":"0","expires":"not-a-date","otp_seed":""}]}`))
	})
	defer server.Close()

	data, err := client.FetchAuthUsers()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.ExpiredUsers != 0 {
		t.Errorf("expected ExpiredUsers=0 for an unparseable expiry, got %d", data.ExpiredUsers)
	}
}

// TestFetchAuthUsers_OTPSeedNeverInMemoryAsString is the sensitivity proof for
// #222: decode a payload containing a real-shaped OTP seed and prove the
// actual seed string is not retrievable anywhere from the returned AuthPosture
// (the type system already guarantees this — HasOTP-equivalent state is a
// bool — but this test also fails loudly if a future edit widens authUserRow
// to carry the seed as a string).
func TestFetchAuthUsers_OTPSeedNeverInMemoryAsString(t *testing.T) {
	const seed = "RGXQFIXS7BT5PRCVKWHWJ5T3Q4ZQXHJB"
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[{"disabled":"0","is_admin":"0","expires":"","otp_seed":"` + seed + `"}]}`))
	})
	defer server.Close()

	data, err := client.FetchAuthUsers()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.UsersWithOTP != 1 {
		t.Fatalf("expected UsersWithOTP=1, got %d", data.UsersWithOTP)
	}
	// AuthPosture has no field capable of holding a string seed value at all —
	// %#v below covers the case where a future change accidentally adds one,
	// since that would leak the seed into this formatted dump.
	dump := fmt.Sprintf("%#v", data)
	if strings.Contains(dump, seed) {
		t.Fatalf("OTP seed leaked into AuthPosture representation: %s", dump)
	}
}

// TestFetchAuthUsers_EmptyOTPSeedNotCounted covers the common case (no TOTP
// configured) alongside the PHP empty-array quirk.
func TestFetchAuthUsers_EmptyOTPSeedNotCounted(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[
			{"disabled":"0","is_admin":"0","expires":"","otp_seed":""},
			{"disabled":"0","is_admin":"0","expires":"","otp_seed":[]}
		]}`))
	})
	defer server.Close()

	data, err := client.FetchAuthUsers()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.UsersWithOTP != 0 {
		t.Errorf("expected UsersWithOTP=0, got %d", data.UsersWithOTP)
	}
}

func TestFetchAuthUsers_Empty(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[]}`))
	})
	defer server.Close()

	data, err := client.FetchAuthUsers()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.UsersTotal != 0 {
		t.Errorf("expected UsersTotal=0, got %d", data.UsersTotal)
	}
}

func TestFetchAuthUsers_APIError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer server.Close()

	_, err := client.FetchAuthUsers()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

func TestFetchAuthAPIKeyCount_Success(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{"total":4,"rowCount":4,"current":1,"rows":[
			{"username":"root","key":"secret-key-material-a","id":"idA"},
			{"username":"root","key":"secret-key-material-b","id":"idB"},
			{"username":"ci-canary","key":"secret-key-material-c","id":"idC"},
			{"username":"testexpireduser","key":"secret-key-material-d","id":"idD"}
		]}`))
	})
	defer server.Close()

	count, err := client.FetchAuthAPIKeyCount()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 4 {
		t.Errorf("expected count=4, got %d", count)
	}
}

func TestFetchAuthAPIKeyCount_Empty(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total":0,"rowCount":0,"current":1,"rows":[]}`))
	})
	defer server.Close()

	count, err := client.FetchAuthAPIKeyCount()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 0 {
		t.Errorf("expected count=0, got %d", count)
	}
}

func TestFetchAuthAPIKeyCount_APIError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer server.Close()

	_, err := client.FetchAuthAPIKeyCount()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

func TestFetchAuthGroupCount_Success(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{"rows":[
			{"gid":"1999","name":"admins","member":"0,2001"},
			{"gid":"2000","name":"testgroup","member":"2001"}
		],"rowCount":2,"total":2,"current":1}`))
	})
	defer server.Close()

	count, err := client.FetchAuthGroupCount()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 2 {
		t.Errorf("expected count=2, got %d", count)
	}
}

func TestFetchAuthGroupCount_APIError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer server.Close()

	_, err := client.FetchAuthGroupCount()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

func TestAuthUserExpired(t *testing.T) {
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name    string
		expires string
		want    bool
	}{
		{"empty never expires", "", false},
		{"past date expired", "01/01/2020", true},
		{"future date not expired", "01/01/2030", false},
		{"unparseable not treated as expired", "garbage", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := authUserExpired(tc.expires, now); got != tc.want {
				t.Errorf("authUserExpired(%q) = %v, want %v", tc.expires, got, tc.want)
			}
		})
	}
}

// TestFetchAuthUsers_PasswordAgeAndShellWarning pins the #583 aggregate
// posture decode. Both fields stay AGGREGATES — no username ever reaches a
// struct field, let alone a label.
//
// Wire evidence (OPNsense core, identical on stable/26.1 and stable/26.7):
//   - Auth/Api/UserController.php:104 and etc/inc/auth.inc:461 both write
//     `pwd_changed_at = microtime(true)` into a TextField (Auth/User.xml:35),
//     so the wire value is a STRING holding float UNIX SECONDS with a
//     microsecond fraction — not milliseconds, not a formatted date. It is
//     written ONLY on a password change, so it is EMPTY for any account whose
//     password predates the feature; upstream itself guards with
//     `empty($userObject->pwd_changed_at) ? 0 : ...` (Auth/Local.php:124).
//   - UserController.php:121 computes shell_warning per search row as
//     `strpos($row['shell'], '/') === 0 && empty($row['is_admin']) ? '1' : '0'`
//     — always present, string '1'/'0'.
func TestFetchAuthUsers_PasswordAgeAndShellWarning(t *testing.T) {
	now := time.Now()
	oldest := now.Add(-400 * 24 * time.Hour)
	newer := now.Add(-10 * 24 * time.Hour)

	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/auth/user/search", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"rows": [
			{"name":"a","pwd_changed_at":"%.6f","shell_warning":"1"},
			{"name":"b","pwd_changed_at":"%.6f","shell_warning":"0"},
			{"name":"c","pwd_changed_at":"","shell_warning":"1"},
			{"name":"d","shell_warning":"0"},
			{"name":"e","pwd_changed_at":"not-a-number","shell_warning":"0"}
		]}`, float64(oldest.UnixNano())/1e9, float64(newer.UnixNano())/1e9)
	})

	data, err := client.FetchAuthUsers()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if data.UsersWithShellWarning != 2 {
		t.Errorf("UsersWithShellWarning = %d, want 2", data.UsersWithShellWarning)
	}
	// Three users have no usable change time (empty, absent, unparseable).
	// They are counted separately rather than folded into the age aggregate:
	// an account that has NEVER had its password changed is the worst case,
	// and silently dropping it would make the oldest-age gauge read healthier
	// than the box actually is.
	if data.UsersWithUnknownPasswordAge != 3 {
		t.Errorf("UsersWithUnknownPasswordAge = %d, want 3", data.UsersWithUnknownPasswordAge)
	}
	if !data.HasOldestPasswordAge {
		t.Fatal("expected HasOldestPasswordAge=true")
	}
	// ~400 days, allowing a generous slack for test execution time.
	wantAge := now.Sub(oldest).Seconds()
	if delta := data.OldestPasswordAgeSeconds - wantAge; delta < -5 || delta > 5 {
		t.Errorf("OldestPasswordAgeSeconds = %v, want ~%v", data.OldestPasswordAgeSeconds, wantAge)
	}
}

// TestFetchAuthUsers_NoPasswordAgeKnown covers the box where NO account has a
// recorded password change: the aggregate must be absent, not 0. A 0 would
// read as "every password was changed this instant", the exact inverse of the
// truth.
func TestFetchAuthUsers_NoPasswordAgeKnown(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/auth/user/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows": [{"name":"root"},{"name":"admin","pwd_changed_at":""}]}`))
	})

	data, err := client.FetchAuthUsers()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.HasOldestPasswordAge {
		t.Errorf("expected HasOldestPasswordAge=false, got age %v", data.OldestPasswordAgeSeconds)
	}
	if data.UsersWithUnknownPasswordAge != 2 {
		t.Errorf("UsersWithUnknownPasswordAge = %d, want 2", data.UsersWithUnknownPasswordAge)
	}
}
