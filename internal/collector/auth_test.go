package collector

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/promslog"
)

// authTestMux builds the three auth endpoints with the real dev-box capture
// shape from #222 (root/ci-canary/testexpireduser, 2 groups, 4 API keys).
func authTestMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/user/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[
			{"name":"root","disabled":"0","expires":"","otp_seed":"","is_admin":"1"},
			{"name":"ci-canary","disabled":"0","expires":"","otp_seed":"","is_admin":"1"},
			{"name":"testexpireduser","disabled":"0","expires":"01/01/2020","otp_seed":"RGXQFIXS7BT5PRCVKWHWJ5T3Q4ZQXHJB","is_admin":"1"}
		],"rowCount":3,"total":3,"current":1}`))
	})
	mux.HandleFunc("/api/auth/user/search_api_key", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total":4,"rowCount":4,"current":1,"rows":[
			{"username":"root","key":"a"},{"username":"root","key":"b"},
			{"username":"ci-canary","key":"c"},{"username":"testexpireduser","key":"d"}
		]}`))
	})
	mux.HandleFunc("/api/auth/group/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[{"name":"admins"},{"name":"testgroup"}],"rowCount":2,"total":2,"current":1}`))
	})
	return mux
}

func TestAuthCollector_Update(t *testing.T) {
	server := httptest.NewServer(authTestMux())
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &authCollector{subsystem: AuthSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	assertNoDuplicateSeries(t, metrics)

	// 2 (users by disabled) + 1 admin + 1 expired + 1 otp + 1 api_keys + 1 groups
	// + 1 shell_warning + 1 password_age_unknown = 9. oldest_password_age_seconds
	// is deliberately absent: no row in this fixture carries pwd_changed_at.
	if len(metrics) != 9 {
		t.Fatalf("expected 9 metrics, got %d", len(metrics))
	}

	for _, m := range metrics {
		labels := getMetricLabels(m)
		switch {
		case hasFqName(m, "opnsense_auth_users"):
			switch labels["disabled"] {
			case "false":
				if v := getMetricValue(m); v != 3 {
					t.Errorf("expected 3 enabled users, got %v", v)
				}
			case "true":
				if v := getMetricValue(m); v != 0 {
					t.Errorf("expected 0 disabled users, got %v", v)
				}
			default:
				t.Errorf("unexpected disabled label value: %q", labels["disabled"])
			}
		case hasFqName(m, "opnsense_auth_admin_users"):
			if v := getMetricValue(m); v != 3 {
				t.Errorf("expected 3 admin users, got %v", v)
			}
		case hasFqName(m, "opnsense_auth_users_expired"):
			if v := getMetricValue(m); v != 1 {
				t.Errorf("expected 1 expired user, got %v", v)
			}
		case hasFqName(m, "opnsense_auth_users_with_otp"):
			if v := getMetricValue(m); v != 1 {
				t.Errorf("expected 1 user with otp, got %v", v)
			}
		case hasFqName(m, "opnsense_auth_api_keys"):
			if v := getMetricValue(m); v != 4 {
				t.Errorf("expected 4 api keys, got %v", v)
			}
		case hasFqName(m, "opnsense_auth_groups"):
			if v := getMetricValue(m); v != 2 {
				t.Errorf("expected 2 groups, got %v", v)
			}
		case hasFqName(m, "opnsense_auth_users_shell_warning"):
			// All three fixture users are admins, and shell_warning is
			// hard-false for an admin whatever their shell.
			if v := getMetricValue(m); v != 0 {
				t.Errorf("expected 0 shell-warning users, got %v", v)
			}
		case hasFqName(m, "opnsense_auth_users_password_age_unknown"):
			if v := getMetricValue(m); v != 3 {
				t.Errorf("expected 3 users with unknown password age, got %v", v)
			}
		default:
			t.Errorf("unexpected metric: %s", m.Desc().String())
		}
	}
}

// TestAuthCollector_NoUsernameLabelsAnywhere is the label-surface sensitivity
// proof for #222: none of the real usernames/group names in the fixture
// (root, ci-canary, testexpireduser, admins, testgroup) may appear as a label
// value anywhere in the collector's output — only aggregate counts.
func TestAuthCollector_NoUsernameLabelsAnywhere(t *testing.T) {
	server := httptest.NewServer(authTestMux())
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &authCollector{subsystem: AuthSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	forbidden := []string{"root", "ci-canary", "testexpireduser", "admins", "testgroup",
		"RGXQFIXS7BT5PRCVKWHWJ5T3Q4ZQXHJB"}
	for _, m := range metrics {
		for k, v := range getMetricLabels(m) {
			for _, f := range forbidden {
				if strings.Contains(k, f) || strings.Contains(v, f) {
					t.Fatalf("forbidden identifier %q leaked into label %s=%q on metric %s", f, k, v, m.Desc().String())
				}
			}
		}
	}
}

func TestAuthCollector_Empty(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/user/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[]}`))
	})
	mux.HandleFunc("/api/auth/user/search_api_key", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total":0,"rowCount":0,"current":1,"rows":[]}`))
	})
	mux.HandleFunc("/api/auth/group/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[],"rowCount":0,"total":0,"current":1}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &authCollector{subsystem: AuthSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	// 9, not 7: the two #583 count aggregates are real zeros on an empty user
	// store. oldest_password_age_seconds still stays absent — there is no
	// oldest password when there are no passwords.
	if len(metrics) != 9 {
		t.Fatalf("expected 9 metrics even with no data, got %d", len(metrics))
	}
	for _, m := range metrics {
		if getMetricValue(m) != 0 {
			t.Errorf("expected all-zero metrics on empty auth store, got %s = %v", m.Desc().String(), getMetricValue(m))
		}
	}
}

func TestAuthCollector_UsersFetchError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/user/search", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	mux.HandleFunc("/api/auth/user/search_api_key", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[]}`))
	})
	mux.HandleFunc("/api/auth/group/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[]}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &authCollector{subsystem: AuthSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	ch := make(chan prometheus.Metric, 8)
	err := c.Update(context.Background(), client, ch)
	close(ch)
	if err == nil {
		t.Fatal("expected error propagated from failed user fetch")
	}
}

func TestAuthCollector_APIKeysFetchError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/user/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[]}`))
	})
	mux.HandleFunc("/api/auth/user/search_api_key", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	mux.HandleFunc("/api/auth/group/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[]}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &authCollector{subsystem: AuthSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	ch := make(chan prometheus.Metric, 8)
	err := c.Update(context.Background(), client, ch)
	close(ch)
	if err == nil {
		t.Fatal("expected error propagated from failed api key fetch")
	}
}

func TestAuthCollector_GroupsFetchError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/user/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[]}`))
	})
	mux.HandleFunc("/api/auth/user/search_api_key", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[]}`))
	})
	mux.HandleFunc("/api/auth/group/search", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &authCollector{subsystem: AuthSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	ch := make(chan prometheus.Metric, 8)
	err := c.Update(context.Background(), client, ch)
	close(ch)
	if err == nil {
		t.Fatal("expected error propagated from failed group fetch")
	}
}

// TestAuthCollector_PasswordAgeAndShellWarning covers the #583 aggregates.
// The fixture deliberately mixes users with and without a recorded password
// change, because those are two different facts and the collector must expose
// both — the maximum alone would read healthier than the box actually is.
func TestAuthCollector_PasswordAgeAndShellWarning(t *testing.T) {
	oldest := float64(time.Now().Add(-365*24*time.Hour).UnixNano()) / 1e9

	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/user/search", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"rows":[
			{"name":"root","is_admin":"1","shell_warning":"0","pwd_changed_at":"%.6f"},
			{"name":"svc","is_admin":"0","shell_warning":"1"},
			{"name":"ops","is_admin":"0","shell_warning":"1","pwd_changed_at":""}
		]}`, oldest)
	})
	mux.HandleFunc("/api/auth/user/search_api_key", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[]}`))
	})
	mux.HandleFunc("/api/auth/group/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[]}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	c := &authCollector{subsystem: AuthSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	metrics := collectMetrics(t, c, newCollectorTestClient(t, server))
	assertNoDuplicateSeries(t, metrics)

	var sawAge, sawUnknown, sawShell bool
	for _, m := range metrics {
		switch {
		case hasFqName(m, "opnsense_auth_oldest_password_age_seconds"):
			sawAge = true
			if v := getMetricValue(m); v < 365*24*3600-5 || v > 365*24*3600+5 {
				t.Errorf("oldest password age = %v, want ~%v", v, 365*24*3600)
			}
		case hasFqName(m, "opnsense_auth_users_password_age_unknown"):
			sawUnknown = true
			if v := getMetricValue(m); v != 2 {
				t.Errorf("users with unknown password age = %v, want 2", v)
			}
		case hasFqName(m, "opnsense_auth_users_shell_warning"):
			sawShell = true
			if v := getMetricValue(m); v != 2 {
				t.Errorf("users with shell warning = %v, want 2", v)
			}
		}
	}
	if !sawAge || !sawUnknown || !sawShell {
		t.Errorf("missing metric(s): age=%v unknown=%v shell=%v", sawAge, sawUnknown, sawShell)
	}
}

// TestAuthCollector_NoPasswordAgeEmitsNoSeries is the #583 zero-fabrication
// guard: on a box where no account has ever recorded a password change, the
// oldest-age gauge must be ABSENT. Emitting 0 would claim every password was
// just rotated, which is the exact inverse of the truth and would make a
// "password older than N days" alert permanently silent.
func TestAuthCollector_NoPasswordAgeEmitsNoSeries(t *testing.T) {
	server := httptest.NewServer(authTestMux())
	defer server.Close()

	c := &authCollector{subsystem: AuthSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	metrics := collectMetrics(t, c, newCollectorTestClient(t, server))

	for _, m := range metrics {
		if hasFqName(m, "opnsense_auth_oldest_password_age_seconds") {
			t.Fatalf("oldest_password_age_seconds must not be emitted when no user has a recorded change (got %v)", getMetricValue(m))
		}
	}
}
