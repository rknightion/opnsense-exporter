package main

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/rknightion/opnsense-exporter/internal/options"
)

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// parseMain parses main.go so the structural guards below can assert things about
// main()'s shape that no runtime test can reach (main() calls os.Exit).
func parseMain(t *testing.T) *ast.File {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}
	return file
}

// mainFuncBody returns the body of func main().
func mainFuncBody(t *testing.T) *ast.BlockStmt {
	t.Helper()
	for _, decl := range parseMain(t).Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == "main" {
			return fn.Body
		}
	}
	t.Fatal("func main() not found in main.go")
	return nil
}

// TestOutOfStartLogMetricsUseInstanceRegisterer guards the two log self-metric
// constructors main builds outside logship.Start. Both must receive the ONE wrapped
// registerer created through logship.SelfMetricsRegisterer; passing
// selfMetricsRegistry directly leaves their series unattributable in a multi-box
// deployment, while wrapping Start's arguments here would double-label them.
func TestOutOfStartLogMetricsUseInstanceRegisterer(t *testing.T) {
	body := mainFuncBody(t)
	wrappedName := ""
	wrapperCalls := 0
	captureCalls := 0
	enrichCalls := 0

	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			if len(node.Lhs) != 1 || len(node.Rhs) != 1 {
				return true
			}
			call, ok := node.Rhs[0].(*ast.CallExpr)
			if !ok || !isPackageCall(call, "logship", "SelfMetricsRegisterer") {
				return true
			}
			wrapperCalls++
			lhs, lhsOK := node.Lhs[0].(*ast.Ident)
			if !lhsOK {
				t.Errorf("logship.SelfMetricsRegisterer result is not assigned to an identifier")
				return true
			}
			if len(call.Args) != 2 || !isIdent(call.Args[0], "selfMetricsRegistry") ||
				!isIdent(call.Args[1], "instanceLabel") {
				t.Errorf("logship.SelfMetricsRegisterer arguments must be (selfMetricsRegistry, instanceLabel)")
				return true
			}
			wrappedName = lhs.Name

		case *ast.CallExpr:
			switch {
			case isPackageCall(node, "capture", "New"):
				captureCalls++
				if len(node.Args) < 2 || wrappedName == "" || !isIdent(node.Args[1], wrappedName) {
					t.Errorf("capture.New registerer is %s, want the identifier returned by logship.SelfMetricsRegisterer",
						astExprName(nodeArg(node, 1)))
				}
			case isPackageCall(node, "enrich", "NewMetrics"):
				enrichCalls++
				if len(node.Args) < 1 || wrappedName == "" || !isIdent(node.Args[0], wrappedName) {
					t.Errorf("enrich.NewMetrics registerer is %s, want the identifier returned by logship.SelfMetricsRegisterer",
						astExprName(nodeArg(node, 0)))
				}
			}
		}
		return true
	})

	if wrapperCalls != 1 {
		t.Errorf("main() creates %d logship.SelfMetricsRegisterer values, want exactly one", wrapperCalls)
	}
	if captureCalls != 1 {
		t.Errorf("main() contains %d capture.New calls, want exactly one guarded call", captureCalls)
	}
	if enrichCalls != 1 {
		t.Errorf("main() contains %d enrich.NewMetrics calls, want exactly one guarded call", enrichCalls)
	}
}

func isPackageCall(call *ast.CallExpr, pkg, name string) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	x, ok := sel.X.(*ast.Ident)
	return ok && x.Name == pkg
}

func isIdent(expr ast.Expr, name string) bool {
	id, ok := expr.(*ast.Ident)
	return ok && id.Name == name
}

func nodeArg(call *ast.CallExpr, index int) ast.Expr {
	if index < 0 || index >= len(call.Args) {
		return nil
	}
	return call.Args[index]
}

func astExprName(expr ast.Expr) string {
	if expr == nil {
		return "<missing>"
	}
	if id, ok := expr.(*ast.Ident); ok {
		return id.Name
	}
	return fmt.Sprintf("%T", expr)
}

// TestEveryDisableSwitchWiredInMain guards the fourth "Adding a New Collector" step that
// no other test covered (#153): each CollectorsDisableSwitch struct field must be
// referenced as `collectorsSwitches.<Field>` in main.go, otherwise the documented
// --exporter.disable-*/--exporter.enable-* flag is generated but silently does nothing at
// runtime (the collector self-registers via init() and would never be gated). It parses
// main.go's AST for the references and diffs them against the reflected struct fields in
// both directions — a field with no reference (unwired flag), and a reference to a field
// that no longer exists (stale block left after a rename/removal).
func TestEveryDisableSwitchWiredInMain(t *testing.T) {
	structFields := map[string]bool{}
	st := reflect.TypeOf(options.CollectorsDisableSwitch{})
	for i := 0; i < st.NumField(); i++ {
		structFields[st.Field(i).Name] = true
	}
	if len(structFields) == 0 {
		t.Fatal("CollectorsDisableSwitch has no fields — reflection failed")
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}
	referenced := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if x, ok := sel.X.(*ast.Ident); ok && x.Name == "collectorsSwitches" {
			referenced[sel.Sel.Name] = true
		}
		return true
	})
	if len(referenced) == 0 {
		t.Fatal("no collectorsSwitches.<Field> references found in main.go — variable renamed?")
	}

	// Forward drift: a struct field (documented flag) with no wiring in main.go is a no-op.
	for field := range structFields {
		if !referenced[field] {
			t.Errorf("CollectorsDisableSwitch.%s is not wired in main.go: its --exporter.* flag would be documented but do nothing", field)
		}
	}
	// Reverse drift: main.go references a field no longer on the struct (stale wiring).
	for field := range referenced {
		if !structFields[field] {
			t.Errorf("main.go references collectorsSwitches.%s, which is not a CollectorsDisableSwitch field (stale wiring)", field)
		}
	}
}

// TestDispatchSubcommand covers the `health` subcommand added for #438: the
// probe must be selected from argv alone, so that a container healthcheck or a
// kubelet exec probe can run it without supplying the server's required flags
// (--opnsense.protocol / --opnsense.address).
func TestDispatchSubcommand(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Run("health is handled", func(t *testing.T) {
		var out, errOut bytes.Buffer
		code, handled := dispatchSubcommand([]string{"health", "--url=" + srv.URL + "/-/healthy"}, &out, &errOut)
		if !handled {
			t.Fatal("health was not handled as a subcommand")
		}
		if code != 0 {
			t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, errOut.String())
		}
	})

	t.Run("health failure propagates a nonzero code", func(t *testing.T) {
		var out, errOut bytes.Buffer
		code, handled := dispatchSubcommand([]string{"health", "--url=http://127.0.0.1:1/-/healthy", "--timeout=200ms"}, &out, &errOut)
		if !handled || code != 1 {
			t.Fatalf("got (code=%d, handled=%v), want (1, true)", code, handled)
		}
	})

	t.Run("server invocations are untouched", func(t *testing.T) {
		for _, args := range [][]string{
			nil,
			{},
			{"--opnsense.protocol=https", "--opnsense.address=fw"},
			{"--version"},
			{"--config.check"},
		} {
			var out, errOut bytes.Buffer
			if code, handled := dispatchSubcommand(args, &out, &errOut); handled {
				t.Errorf("args %v were swallowed by the subcommand dispatcher (code=%d)", args, code)
			}
		}
	})
}

// TestHealthSubcommandDispatchedBeforeFlagParsing pins the ordering the probe
// depends on: dispatchSubcommand must run before options.Init(), or the probe
// would inherit the server's required flags and could never run from a
// healthcheck. A structural check, because the ordering is invisible at runtime
// until the day it breaks in someone's container.
func TestHealthSubcommandDispatchedBeforeFlagParsing(t *testing.T) {
	body := mainFuncBody(t)
	dispatchAt, initAt := -1, -1
	for i, stmt := range body.List {
		ast.Inspect(stmt, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fn := call.Fun.(type) {
			case *ast.Ident:
				if fn.Name == "dispatchSubcommand" && dispatchAt < 0 {
					dispatchAt = i
				}
			case *ast.SelectorExpr:
				if x, ok := fn.X.(*ast.Ident); ok && x.Name == "options" && fn.Sel.Name == "Init" && initAt < 0 {
					initAt = i
				}
			}
			return true
		})
	}
	if dispatchAt < 0 {
		t.Fatal("main() does not call dispatchSubcommand")
	}
	if initAt < 0 {
		t.Fatal("main() does not call options.Init()")
	}
	if dispatchAt > initAt {
		t.Errorf("dispatchSubcommand runs at statement %d, after options.Init() at %d: "+
			"the health probe must not depend on the server flag parser", dispatchAt, initAt)
	}
}

// validatorAllowlist is the set of error-returning validators main() may call
// directly, with the reason each is exempt.
var validatorAllowlist = map[string]string{
	// Runs BEFORE options.Init(), so it cannot live in resolveOptions (which reads
	// parsed values). Both the preflight and a real start pass through it, because
	// it sits above the --config.check branch — so it cannot drift either.
	"CheckRemovedFlagsFromProcess": "must run before flag parsing",
}

// TestConfigValidationCannotDriftFromStartup is the anti-drift guarantee #446
// asks for. Rather than asserting that two code paths happen to agree today, it
// removes the possibility of a second path: every exported internal/options
// accessor that can return an error must be called from resolveOptions, which is
// the single function both --config.check and a real start go through.
//
// Add a new validating accessor and call it inline in main() and this fails,
// naming it — which is the moment the preflight would otherwise have started
// passing configurations the exporter rejects.
func TestConfigValidationCannotDriftFromStartup(t *testing.T) {
	validators := errorReturningOptionsFuncs(t)
	if len(validators) < 5 {
		t.Fatalf("found only %d error-returning options accessors; the scan is broken", len(validators))
	}

	calledInMain := optionsCallsIn(t, "main")
	calledInResolve := optionsCallsIn(t, "resolveOptions")

	for name := range validators {
		if _, exempt := validatorAllowlist[name]; exempt {
			continue
		}
		if calledInMain[name] {
			t.Errorf("main() calls options.%s() directly: move it into resolveOptions(), "+
				"or --config.check will not validate what a real start does", name)
		}
	}

	// The reverse direction: the resolver must actually be exercising the validators
	// the exporter depends on. A resolver that validated nothing would pass the check
	// above trivially.
	for _, must := range []string{"OPNSense", "Flow", "Logs", "LogsSyslog", "OTLP", "Pyroscope", "ValidateMetricsPath"} {
		if !calledInResolve[must] {
			t.Errorf("resolveOptions() does not call options.%s(): the preflight would skip its validation", must)
		}
	}

	// Validators that live outside internal/options but are equally load-bearing.
	for _, fn := range []struct{ pkg, name string }{
		{"collector", "ValidatePollOverrideNames"},
		{"netflow", "ParseCaptureMode"},
		{"web", "Validate"},
	} {
		if !callsIn(t, "resolveOptions", fn.pkg)[fn.name] {
			t.Errorf("resolveOptions() does not call %s.%s(): the preflight would skip it", fn.pkg, fn.name)
		}
		if callsIn(t, "main", fn.pkg)[fn.name] {
			t.Errorf("main() calls %s.%s() directly instead of via resolveOptions()", fn.pkg, fn.name)
		}
	}
}

// errorReturningOptionsFuncs returns the names of every exported function in
// internal/options whose results include an error.
func errorReturningOptionsFuncs(t *testing.T) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir("internal/options")
	if err != nil {
		t.Fatalf("read internal/options: %v", err)
	}
	out := map[string]bool{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join("internal/options", entry.Name()), nil, 0)
		if err != nil {
			t.Fatalf("parse internal/options/%s: %v", entry.Name(), err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !fn.Name.IsExported() || fn.Type.Results == nil {
				continue
			}
			for _, res := range fn.Type.Results.List {
				if id, ok := res.Type.(*ast.Ident); ok && id.Name == "error" {
					out[fn.Name.Name] = true
				}
			}
		}
	}
	return out
}

// callsIn returns the names of pkg.<Name>(...) calls made inside the named
// top-level function of main.go.
func callsIn(t *testing.T, funcName, pkg string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	var target *ast.FuncDecl
	for _, decl := range parseMain(t).Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == funcName {
			target = fn
		}
	}
	if target == nil {
		t.Fatalf("func %s not found in main.go", funcName)
	}
	ast.Inspect(target.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if x, ok := sel.X.(*ast.Ident); ok && x.Name == pkg {
			out[sel.Sel.Name] = true
		}
		return true
	})
	return out
}

func optionsCallsIn(t *testing.T, funcName string) map[string]bool {
	t.Helper()
	return callsIn(t, funcName, "options")
}

// TestRunConfigCheck covers the preflight's contract: a stable nonzero exit with
// every problem named, and a zero exit whose output carries no secret.
func TestRunConfigCheck(t *testing.T) {
	t.Run("failures exit 1 and are all reported", func(t *testing.T) {
		var out, errOut bytes.Buffer
		errs := []error{
			errors.New("invalid --collector.poll-interval-override: unknown collector \"gatways\""),
			errors.New("--web.config.file: no such file"),
		}
		if code := runConfigCheck(&startupConfig{}, errs, &out, &errOut); code != 1 {
			t.Fatalf("exit code = %d, want 1", code)
		}
		for _, want := range []string{"gatways", "--web.config.file", "2 problem"} {
			if !strings.Contains(errOut.String(), want) {
				t.Errorf("stderr missing %q; got:\n%s", want, errOut.String())
			}
		}
	})

	t.Run("success exits 0 and never prints a secret", func(t *testing.T) {
		const apiKey = "SUPERSECRETKEYVALUE"
		const apiSecret = "SUPERSECRETSECRETVALUE"
		t.Setenv("OPNSENSE_EXPORTER_OPS_PROTOCOL", "https")
		t.Setenv("OPNSENSE_EXPORTER_OPS_API", "fw.example.com")
		t.Setenv("OPNSENSE_EXPORTER_OPS_API_KEY", apiKey)
		t.Setenv("OPNSENSE_EXPORTER_OPS_API_SECRET", apiSecret)
		if _, err := kingpin.CommandLine.Parse(nil); err != nil {
			t.Fatalf("parse: %v", err)
		}

		var out, errOut bytes.Buffer
		if code := runConfigCheck(&startupConfig{}, nil, &out, &errOut); code != 0 {
			t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, errOut.String())
		}
		printed := out.String()
		if strings.Contains(printed, apiKey) || strings.Contains(printed, apiSecret) {
			t.Fatalf("config check printed a secret:\n%s", printed)
		}
		if !strings.Contains(printed, "config check OK") {
			t.Errorf("missing the OK line:\n%s", printed)
		}
		// The excluded checks must be stated, not implied (#446 asks for this
		// explicitly): an operator has to know a green preflight says nothing about
		// whether the firewall is reachable.
		if !strings.Contains(printed, "/-/ready") {
			t.Errorf("output does not say which checks are excluded:\n%s", printed)
		}
	})
}

// TestResolveOptionsReportsEveryProblem walks the failure classes #446 lists.
// Each case drives the REAL parser over env vars, so it exercises exactly the
// path a deployment does.
func TestResolveOptionsReportsEveryProblem(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "api-key")
	if err := os.WriteFile(keyFile, []byte("a-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	baseEnv := map[string]string{
		"OPNSENSE_EXPORTER_OPS_PROTOCOL":   "https",
		"OPNSENSE_EXPORTER_OPS_API":        "fw.example.com",
		"OPNSENSE_EXPORTER_OPS_API_KEY":    "a-key",
		"OPNSENSE_EXPORTER_OPS_API_SECRET": "a-secret",
	}

	// NOTE: these subtests share one process-global kingpin flag set, and a
	// repeatable map flag accumulates across parses. The valid case therefore runs
	// FIRST and the poll-interval-override case LAST.
	cases := []struct {
		name string
		env  map[string]string
		args []string
		want string // substring of the reported problem; "" means the config must be valid
	}{
		{name: "valid production-equivalent config", want: ""},
		{
			name: "unreadable secret file",
			env:  map[string]string{"OPS_API_KEY_FILE": filepath.Join(t.TempDir(), "absent")},
			want: "no such file",
		},
		{
			name: "missing credential",
			env:  map[string]string{"OPNSENSE_EXPORTER_OPS_API_KEY": ""},
			want: "api-key must be set",
		},
		{
			name: "metrics path collides with a reserved route",
			env:  map[string]string{"OPNSENSE_EXPORTER_WEB_TELEMETRY_PATH": "/-/healthy"},
			want: "reserved",
		},
		{
			name: "unreadable TLS keypair on the syslog receiver",
			env: map[string]string{
				"OPNSENSE_EXPORTER_LOGS_ENABLED":              "true",
				"OPNSENSE_EXPORTER_LOGS_SINK":                 "stdout",
				"OPNSENSE_EXPORTER_LOGS_SYSLOG_ENABLED":       "true",
				"OPNSENSE_EXPORTER_LOGS_SYSLOG_LISTEN_TLS":    ":6514",
				"OPNSENSE_EXPORTER_LOGS_SYSLOG_TLS_CERT_FILE": filepath.Join(t.TempDir(), "absent.pem"),
				"OPNSENSE_EXPORTER_LOGS_SYSLOG_TLS_KEY_FILE":  filepath.Join(t.TempDir(), "absent-key.pem"),
			},
			want: "syslog",
		},
		{
			name: "conflicting receiver modes (zenarmor over syslog with no syslog receiver)",
			env: map[string]string{
				"OPNSENSE_EXPORTER_LOGS_ENABLED":            "true",
				"OPNSENSE_EXPORTER_LOGS_SINK":               "stdout",
				"OPNSENSE_EXPORTER_LOGS_ZENARMOR_ENABLED":   "true",
				"OPNSENSE_EXPORTER_LOGS_ZENARMOR_TRANSPORT": "syslog",
				"OPNSENSE_EXPORTER_LOGS_SYSLOG_ENABLED":     "false",
			},
			want: "zenarmor",
		},
		{
			// --web.config.file is an exporter-toolkit flag with no env var, so it is
			// exercised as an argument.
			name: "unreadable web TLS config",
			args: []string{"--web.config.file=" + filepath.Join(t.TempDir(), "absent.yml")},
			want: "--web.config.file",
		},
		{
			name: "unknown collector and invalid duration in poll-interval overrides",
			env: map[string]string{
				"OPNSENSE_EXPORTER_COLLECTOR_POLL_INTERVAL_OVERRIDE": "gatways=10s\ngateways=10sec",
			},
			want: "--collector.poll-interval-override",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range baseEnv {
				t.Setenv(k, v)
			}
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			if _, err := kingpin.CommandLine.Parse(tc.args); err != nil {
				// A parse failure is itself a nonzero-exit config error, which is the
				// contract; only assert on it when that is what the case expects.
				if tc.want == "" {
					t.Fatalf("parse failed for a config expected to be valid: %v", err)
				}
				if !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("parse error %q does not mention %q", err, tc.want)
				}
				return
			}
			_, errs := resolveOptions()
			joined := errorStrings(errs)
			if tc.want == "" {
				if len(errs) != 0 {
					t.Fatalf("valid config reported problems: %s", joined)
				}
				return
			}
			if !strings.Contains(joined, tc.want) {
				t.Fatalf("problems %q do not mention %q", joined, tc.want)
			}
		})
	}
}

func errorStrings(errs []error) string {
	parts := make([]string, 0, len(errs))
	for _, err := range errs {
		parts = append(parts, err.Error())
	}
	return strings.Join(parts, "; ")
}

// TestGracefulShutdownDrainsInFlightRequest covers #161: a slow request in flight when
// the signal arrives must complete (not be severed), telemetry stop hooks must run, and
// the log must reflect the actual signal received (SIGINT -> "interrupt", not a
// hardcoded "SIGTERM").
func TestGracefulShutdownDrainsInFlightRequest(t *testing.T) {
	started := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		time.Sleep(300 * time.Millisecond)
		_, _ = w.Write([]byte("OK"))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	type result struct {
		body   string
		status int
		err    error
	}
	resCh := make(chan result, 1)
	go func() {
		resp, err := http.Get(ts.URL + "/metrics")
		if err != nil {
			resCh <- result{err: err}
			return
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		resCh <- result{body: string(b), status: resp.StatusCode}
	}()

	<-started // request is now in flight inside the handler

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	var pollStopped, logsStopped, otlpStopped, profStopped bool
	gracefulShutdown(ts.Config, syscall.SIGINT,
		func() { pollStopped = true },
		func() { logsStopped = true },
		func() { otlpStopped = true },
		func() { profStopped = true },
		logger)

	res := <-resCh
	if res.err != nil {
		t.Fatalf("in-flight request was severed: %v", res.err)
	}
	if res.status != http.StatusOK || res.body != "OK" {
		t.Errorf("in-flight request did not complete cleanly: status=%d body=%q", res.status, res.body)
	}
	if !pollStopped || !logsStopped || !otlpStopped || !profStopped {
		t.Errorf("stop hooks not run: poll=%v logs=%v otlp=%v prof=%v", pollStopped, logsStopped, otlpStopped, profStopped)
	}
	// SIGINT stringifies to "interrupt"; assert the actual signal, not a hardcoded one.
	if !strings.Contains(buf.String(), "interrupt") {
		t.Errorf("log did not reflect the actual signal (SIGINT); log=%q", buf.String())
	}
}

// TestResolveInstanceLabel pins the deterministic instance-label resolution
// (#75): the value must never depend on startup timing or the box's momentary
// reachability.
func TestResolveInstanceLabel(t *testing.T) {
	log := quietLogger()

	t.Run("explicit label always wins", func(t *testing.T) {
		got, err := resolveInstanceLabel("fw-01", "10.0.0.1", true, func() (string, error) {
			t.Fatal("lookup must not be called when an explicit label is set")
			return "", nil
		}, log)
		if err != nil || got != "fw-01" {
			t.Fatalf("got (%q, %v), want (\"fw-01\", nil)", got, err)
		}
	})

	t.Run("default uses address without calling the API (deterministic)", func(t *testing.T) {
		calls := 0
		got, err := resolveInstanceLabel("", "10.0.0.1", false, func() (string, error) {
			calls++
			return "should-not-be-used", nil
		}, log)
		if err != nil || got != "10.0.0.1" {
			t.Fatalf("got (%q, %v), want (\"10.0.0.1\", nil)", got, err)
		}
		if calls != 0 {
			t.Errorf("lookup was called %d times; the address default must not depend on the API", calls)
		}
	})

	t.Run("use-hostname success", func(t *testing.T) {
		got, err := resolveInstanceLabel("", "10.0.0.1", true, func() (string, error) {
			return "opnsense.example.com", nil
		}, log)
		if err != nil || got != "opnsense.example.com" {
			t.Fatalf("got (%q, %v), want (\"opnsense.example.com\", nil)", got, err)
		}
	})

	t.Run("use-hostname lookup failure fails startup, never falls back to address", func(t *testing.T) {
		got, err := resolveInstanceLabel("", "10.0.0.1", true, func() (string, error) {
			return "", errors.New("unreachable")
		}, log)
		if err == nil {
			t.Fatalf("expected an error, got label %q (must not silently fall back to the address)", got)
		}
	})

	t.Run("use-hostname empty hostname fails startup", func(t *testing.T) {
		_, err := resolveInstanceLabel("", "10.0.0.1", true, func() (string, error) {
			return "", nil
		}, log)
		if err == nil {
			t.Fatal("expected an error for an empty hostname")
		}
	})

	t.Run("deterministic across repeated calls regardless of a flaky/slow API", func(t *testing.T) {
		// With the default (address) path, a lookup that would return different
		// values on each call must not affect the result.
		seq := []string{"a", "b", "c"}
		i := 0
		lookup := func() (string, error) { v := seq[i%len(seq)]; i++; return v, nil }
		first, _ := resolveInstanceLabel("", "10.0.0.1", false, lookup, log)
		for range 5 {
			got, _ := resolveInstanceLabel("", "10.0.0.1", false, lookup, log)
			if got != first {
				t.Fatalf("non-deterministic label: %q vs %q", got, first)
			}
		}
	})
}
