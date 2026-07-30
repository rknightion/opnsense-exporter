package opnsense

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"
)

func TestFetchActivity_Success(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/diagnostics/activity/get_activity" {
			t.Errorf("expected path /api/diagnostics/activity/get_activity, got %s", r.URL.Path)
		}
		w.Write([]byte(`{
			"headers": [
				"last pid: 65652;  load averages:  0.74,  0.52,  0.49  up 23+03:58:03    17:13:41",
				"849 threads:   13 running, 802 sleeping, 34 waiting",
				"CPU:  1.3% user,  0.0% nice,  2.2% system,  0.1% interrupt, 96.4% idle",
				"Mem: 5249M Active, 3393M Inact, 5446M Laundry, 13G Wired, 372K Buf, 3900M Free",
				"ARC: 8970M Total, 4571M MFU, 3776M MRU, 34M Anon, 67M Header, 517M Other",
				"     7809M Compressed, 13G Uncompressed, 1.74:1 Ratio",
				"Swap: 10G Total, 433M Used, 9807M Free, 4% Inuse"
			],
			"details": []
		}`))
	})
	defer server.Close()

	data, err := client.FetchActivity()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if data.ThreadsTotal != 849 {
		t.Errorf("expected ThreadsTotal=849, got %d", data.ThreadsTotal)
	}
	if data.ThreadsRunning != 13 {
		t.Errorf("expected ThreadsRunning=13, got %d", data.ThreadsRunning)
	}
	if data.ThreadsSleeping != 802 {
		t.Errorf("expected ThreadsSleeping=802, got %d", data.ThreadsSleeping)
	}
	if data.ThreadsWaiting != 34 {
		t.Errorf("expected ThreadsWaiting=34, got %d", data.ThreadsWaiting)
	}
}

func TestFetchActivity_EmptyHeaders(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/diagnostics/activity/get_activity" {
			t.Errorf("expected path /api/diagnostics/activity/get_activity, got %s", r.URL.Path)
		}
		w.Write([]byte(`{
			"headers": [],
			"details": []
		}`))
	})
	defer server.Close()

	data, err := client.FetchActivity()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if data.ThreadsTotal != 0 {
		t.Errorf("expected ThreadsTotal=0, got %d", data.ThreadsTotal)
	}
	if data.ThreadsRunning != 0 {
		t.Errorf("expected ThreadsRunning=0, got %d", data.ThreadsRunning)
	}
	if data.ThreadsSleeping != 0 {
		t.Errorf("expected ThreadsSleeping=0, got %d", data.ThreadsSleeping)
	}
	if data.ThreadsWaiting != 0 {
		t.Errorf("expected ThreadsWaiting=0, got %d", data.ThreadsWaiting)
	}
}

func TestFetchActivity_MalformedHeaders(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/diagnostics/activity/get_activity" {
			t.Errorf("expected path /api/diagnostics/activity/get_activity, got %s", r.URL.Path)
		}
		w.Write([]byte(`{
			"headers": [
				"some random header text",
				"no threads info here",
				"CPU usage is unknown"
			],
			"details": []
		}`))
	})
	defer server.Close()

	data, err := client.FetchActivity()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if data.ThreadsTotal != 0 {
		t.Errorf("expected ThreadsTotal=0, got %d", data.ThreadsTotal)
	}
	if data.ThreadsRunning != 0 {
		t.Errorf("expected ThreadsRunning=0, got %d", data.ThreadsRunning)
	}
}

// TestFetchActivity_ZombieBetweenSleepingAndWaiting guards #82: FreeBSD's top
// inserts non-zero states (zombie/stopped/starting) in a fixed order, breaking a
// regex that requires running,sleeping,waiting to be contiguous. Each state must
// be parsed independently.
func TestFetchActivity_ZombieBetweenSleepingAndWaiting(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"headers": [
				"879 threads:   13 running, 831 sleeping, 1 zombie, 34 waiting",
				"CPU:  1.3% user,  0.0% nice,  2.2% system,  0.1% interrupt, 96.4% idle"
			],
			"details": []
		}`))
	})
	defer server.Close()

	data, err := client.FetchActivity()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.ThreadsTotal != 879 {
		t.Errorf("expected ThreadsTotal=879, got %d", data.ThreadsTotal)
	}
	if data.ThreadsRunning != 13 {
		t.Errorf("expected ThreadsRunning=13, got %d", data.ThreadsRunning)
	}
	if data.ThreadsSleeping != 831 {
		t.Errorf("expected ThreadsSleeping=831, got %d", data.ThreadsSleeping)
	}
	if data.ThreadsWaiting != 34 {
		t.Errorf("expected ThreadsWaiting=34, got %d", data.ThreadsWaiting)
	}
	// CPU must still parse from the following header despite the thread-state change.
}

// TestFetchActivity_WaitingAbsent guards #82: top only prints non-zero states, so
// a header can omit waiting entirely. The present states must still parse and the
// absent one defaults to 0 without failing the whole parse.
func TestFetchActivity_WaitingAbsent(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"headers": [
				"8 threads:   2 running, 6 sleeping"
			],
			"details": []
		}`))
	})
	defer server.Close()

	data, err := client.FetchActivity()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.ThreadsTotal != 8 {
		t.Errorf("expected ThreadsTotal=8, got %d", data.ThreadsTotal)
	}
	if data.ThreadsRunning != 2 {
		t.Errorf("expected ThreadsRunning=2, got %d", data.ThreadsRunning)
	}
	if data.ThreadsSleeping != 6 {
		t.Errorf("expected ThreadsSleeping=6, got %d", data.ThreadsSleeping)
	}
	if data.ThreadsWaiting != 0 {
		t.Errorf("expected ThreadsWaiting=0 (absent), got %d", data.ThreadsWaiting)
	}
}

// TestFetchActivity_StartingBeforeRunning guards #82: a starting/stopped segment
// can precede running; the remaining states must still parse correctly.
func TestFetchActivity_StartingBeforeRunning(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"headers": [
				"900 threads:   1 starting, 13 running, 850 sleeping, 1 stopped, 35 waiting"
			],
			"details": []
		}`))
	})
	defer server.Close()

	data, err := client.FetchActivity()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.ThreadsTotal != 900 {
		t.Errorf("expected ThreadsTotal=900, got %d", data.ThreadsTotal)
	}
	if data.ThreadsRunning != 13 {
		t.Errorf("expected ThreadsRunning=13, got %d", data.ThreadsRunning)
	}
	if data.ThreadsSleeping != 850 {
		t.Errorf("expected ThreadsSleeping=850, got %d", data.ThreadsSleeping)
	}
	if data.ThreadsWaiting != 35 {
		t.Errorf("expected ThreadsWaiting=35, got %d", data.ThreadsWaiting)
	}
}

// TestFetchActivity_WarnsOnUnparsableThreadStates guards #82's acceptance
// criterion: when a "threads:" header is present but no state segment parses, the
// failure must be logged, not silent.
func TestFetchActivity_WarnsOnUnparsableThreadStates(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"headers": [
				"42 threads: something totally unexpected here"
			],
			"details": []
		}`))
	})
	defer server.Close()

	var buf bytes.Buffer
	client.log = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	data, err := client.FetchActivity()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The total is still recoverable from the header prefix.
	if data.ThreadsTotal != 42 {
		t.Errorf("expected ThreadsTotal=42, got %d", data.ThreadsTotal)
	}
	if !strings.Contains(buf.String(), "thread-state") {
		t.Errorf("expected a warning about unparsable thread states; got log: %q", buf.String())
	}
}

func TestFetchActivity_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchActivity()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}

// TestFetchActivity_ThreadStateMatchesAreBounded covers #321: the thread-state
// scan used FindAllStringSubmatch(header, -1), so an appliance-controlled
// header — bounded only by the 64 MiB response cap — could make the client
// materialize millions of submatch slices (allocation amplification; this is
// NOT ReDoS, Go's RE2 cannot backtrack). Only 7 thread states exist and
// FreeBSD's top prints each at most once, so a small cap cannot lose real
// data. The parse of a pathological header must stay finite and the last
// occurrence of each state must still be what wins for a normal header.
func TestFetchActivity_ThreadStateMatchesAreBounded(t *testing.T) {
	// Far more state segments than any real `top` header carries.
	var sb strings.Builder
	sb.WriteString("849 threads:")
	for i := 0; i < 100000; i++ {
		sb.WriteString(" 1 running,")
	}
	header := sb.String()

	if got := len(parseThreadStates(header)); got > threadStateMatchLimit {
		t.Fatalf("thread-state scan returned %d matches; expected at most %d", got, threadStateMatchLimit)
	}
	if threadStateMatchLimit <= 0 || threadStateMatchLimit > 64 {
		t.Fatalf("threadStateMatchLimit=%d is outside the sane range (must bound allocation, must exceed the 7 real states)", threadStateMatchLimit)
	}

	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"headers":[%q],"details":[]}`, header)
	})
	defer server.Close()

	data, err := client.FetchActivity()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.ThreadsTotal != 849 {
		t.Errorf("expected ThreadsTotal=849, got %d", data.ThreadsTotal)
	}
	if data.ThreadsRunning != 1 {
		t.Errorf("expected ThreadsRunning=1, got %d", data.ThreadsRunning)
	}
}

// TestFetchActivity_AllSevenThreadStatesParse pins the lower bound of the
// #321 cap: every state FreeBSD's top can print must still be seen, so the
// bound can never be tightened below the real maximum.
func TestFetchActivity_AllSevenThreadStatesParse(t *testing.T) {
	const header = "849 threads:   1 starting, 13 running, 802 sleeping, 2 stopped, 3 zombie, 34 waiting, 5 lock"

	states := parseThreadStates(header)
	if len(states) != 7 {
		t.Fatalf("expected all 7 thread states to be captured under the cap, got %d", len(states))
	}

	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"headers":[%q],"details":[]}`, header)
	})
	defer server.Close()

	data, err := client.FetchActivity()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.ThreadsRunning != 13 || data.ThreadsSleeping != 802 || data.ThreadsWaiting != 34 {
		t.Errorf("expected running/sleeping/waiting = 13/802/34, got %d/%d/%d",
			data.ThreadsRunning, data.ThreadsSleeping, data.ThreadsWaiting)
	}
}

// activityDetailsFixture is a small, realistic `top -aHSTn` details table. The row
// shape is the real capture quoted in #552.
//
// It is deliberately built so that a NAIVE implementation fails:
//
//   - PID 100 (python3) has FOUR thread rows, and every one of them reports the
//     PROCESS's RES of 512M. Summing RES across rows gives 2048M — four times the
//     truth. The correct answer counts each distinct PID's RES exactly once per
//     bucket.
//   - WCPU is genuinely per-thread and DOES sum: 4 x 5.00% = 20.00%.
//   - The two [idle{...}] rows are the top rows by WCPU on any healthy box and must
//     be excluded from every aggregation, or they dominate all three.
const activityDetailsFixture = `[
	{"C":"10","PID":"11","THR":"100013","USERNAME":"root","PRI":"199","NICE":"ki31",
	 "SIZE":"0B","RES":"192K","STATE":"CPU10","TIME":"41.7H","WCPU":"98.27%",
	 "COMMAND":"[idle{idle: cpu10}]"},
	{"C":"11","PID":"11","THR":"100014","USERNAME":"root","PRI":"199","NICE":"ki31",
	 "SIZE":"0B","RES":"192K","STATE":"CPU11","TIME":"41.6H","WCPU":"97.13%",
	 "COMMAND":"[idle{idle: cpu11}]"},
	{"C":"0","PID":"100","THR":"100201","USERNAME":"www","PRI":"20","NICE":"0",
	 "SIZE":"1024M","RES":"512M","STATE":"nanslp","TIME":"1:02","WCPU":"5.00%",
	 "COMMAND":"python3{python3}"},
	{"C":"1","PID":"100","THR":"100202","USERNAME":"www","PRI":"20","NICE":"0",
	 "SIZE":"1024M","RES":"512M","STATE":"nanslp","TIME":"1:02","WCPU":"5.00%",
	 "COMMAND":"python3{python3}"},
	{"C":"2","PID":"100","THR":"100203","USERNAME":"www","PRI":"20","NICE":"0",
	 "SIZE":"1024M","RES":"512M","STATE":"nanslp","TIME":"1:02","WCPU":"5.00%",
	 "COMMAND":"python3{python3}"},
	{"C":"3","PID":"100","THR":"100204","USERNAME":"www","PRI":"20","NICE":"0",
	 "SIZE":"1024M","RES":"512M","STATE":"nanslp","TIME":"1:02","WCPU":"5.00%",
	 "COMMAND":"python3{python3}"},
	{"C":"4","PID":"200","THR":"100301","USERNAME":"root","PRI":"20","NICE":"0",
	 "SIZE":"64M","RES":"32M","STATE":"select","TIME":"0:10","WCPU":"1.50%",
	 "COMMAND":"unbound"},
	{"C":"5","PID":"300","THR":"100401","USERNAME":"root","PRI":"-8","NICE":"0",
	 "SIZE":"0B","RES":"16M","STATE":"-","TIME":"0:01","WCPU":"0.20%",
	 "COMMAND":"[zfskern{txg_thread_enter}]"}
]`

const mib = 1024 * 1024

// TestParseActivityDetails_DedupesResidentMemoryByPID is the acceptance proof for
// #552's memory trap. `top -aHSTn` prints one row per THREAD and every thread of a
// process reports that PROCESS's RES, so naive summation multiplies a process's
// memory by its thread count. This fails under naive summation (2048M) and passes
// only with per-PID dedupe (512M).
func TestParseActivityDetails_DedupesResidentMemoryByPID(t *testing.T) {
	agg := parseActivityDetailsJSON(t, activityDetailsFixture)

	if got, want := agg.MemoryBytesByCommand["python3"], float64(512*mib); got != want {
		t.Errorf("MemoryBytesByCommand[python3] = %v, want %v (naive per-thread summation gives %v)",
			got, want, float64(4*512*mib))
	}
	if got, want := agg.MemoryBytesByUser["www"], float64(512*mib); got != want {
		t.Errorf("MemoryBytesByUser[www] = %v, want %v (naive per-thread summation gives %v)",
			got, want, float64(4*512*mib))
	}
	// root owns two distinct PIDs, so its memory is a genuine sum of two RES values.
	if got, want := agg.MemoryBytesByUser["root"], float64(32*mib+16*mib); got != want {
		t.Errorf("MemoryBytesByUser[root] = %v, want %v", got, want)
	}
}

// TestParseActivityDetails_SumsWCPUPerThread pins the other half of the trap: WCPU is
// genuinely per-thread, so it must NOT be deduped by PID.
func TestParseActivityDetails_SumsWCPUPerThread(t *testing.T) {
	agg := parseActivityDetailsJSON(t, activityDetailsFixture)

	if got, want := agg.CPUPercentByCommand["python3"], 20.0; got != want {
		t.Errorf("CPUPercentByCommand[python3] = %v, want %v (4 threads x 5.00%%)", got, want)
	}
	if got, want := agg.CPUPercentByUser["www"], 20.0; got != want {
		t.Errorf("CPUPercentByUser[www] = %v, want %v", got, want)
	}
	if got, want := agg.CPUPercentByUser["root"], 1.7; got < want-0.001 || got > want+0.001 {
		t.Errorf("CPUPercentByUser[root] = %v, want %v", got, want)
	}
}

func TestParseActivityDetails_ThreadsPerCommand(t *testing.T) {
	agg := parseActivityDetailsJSON(t, activityDetailsFixture)

	for command, want := range map[string]float64{"python3": 4, "unbound": 1, "zfskern": 1} {
		if got := agg.ThreadsByCommand[command]; got != want {
			t.Errorf("ThreadsByCommand[%s] = %v, want %v", command, got, want)
		}
	}
}

// TestParseActivityDetails_ExcludesIdle pins that the kernel idle threads are dropped
// entirely. They are the top rows by WCPU at ~98% on every healthy box, so leaving
// them in would dominate all three aggregations and make every panel useless.
func TestParseActivityDetails_ExcludesIdle(t *testing.T) {
	agg := parseActivityDetailsJSON(t, activityDetailsFixture)

	if _, ok := agg.CPUPercentByCommand["idle"]; ok {
		t.Error("idle must be excluded from CPUPercentByCommand")
	}
	if _, ok := agg.ThreadsByCommand["idle"]; ok {
		t.Error("idle must be excluded from ThreadsByCommand")
	}
	if _, ok := agg.MemoryBytesByCommand["idle"]; ok {
		t.Error("idle must be excluded from MemoryBytesByCommand")
	}
	// root's CPU must not carry the two idle threads' ~195%.
	if agg.CPUPercentByUser["root"] > 50 {
		t.Errorf("idle threads leaked into CPUPercentByUser[root] = %v", agg.CPUPercentByUser["root"])
	}
}

func TestNormalizeCommand(t *testing.T) {
	for raw, want := range map[string]string{
		"[idle{idle: cpu10}]":         "idle",
		"[zfskern{txg_thread_enter}]": "zfskern",
		"python3{python3}":            "python3",
		"unbound":                     "unbound",
		"[kernel{if_io_tqg_3}]":       "kernel",
		"  /usr/local/sbin/haproxy  ": "/usr/local/sbin/haproxy",
		"[intr{irq264: virtio_pci2}]": "intr",
		"":                            "",
	} {
		if got := normalizeCommand(raw); got != want {
			t.Errorf("normalizeCommand(%q) = %q, want %q", raw, got, want)
		}
	}
}

// TestParseActivityDetails_SkipsUnparseableRows pins rule G: a row whose WCPU or RES
// cannot be parsed is SKIPPED, never counted as a zero. A fabricated zero would drag
// a command's memory figure down without any signal that it had done so.
func TestParseActivityDetails_SkipsUnparseableRows(t *testing.T) {
	agg := parseActivityDetailsJSON(t, `[
		{"PID":"1","USERNAME":"root","RES":"not-a-size","WCPU":"1.00%","COMMAND":"bad-res"},
		{"PID":"2","USERNAME":"root","RES":"8M","WCPU":"n/a","COMMAND":"bad-cpu"},
		{"PID":"3","USERNAME":"root","RES":"8M","WCPU":"1.00%","COMMAND":""},
		{"PID":"","USERNAME":"root","RES":"8M","WCPU":"1.00%","COMMAND":"no-pid"},
		{"PID":"5","USERNAME":"","RES":"8M","WCPU":"1.00%","COMMAND":"no-user"},
		{"PID":"6","USERNAME":"root","RES":"8M","WCPU":"2.00%","COMMAND":"good"}
	]`)

	if len(agg.CPUPercentByCommand) != 1 {
		t.Fatalf("expected exactly one surviving command, got %v", agg.CPUPercentByCommand)
	}
	if got := agg.CPUPercentByCommand["good"]; got != 2.0 {
		t.Errorf("CPUPercentByCommand[good] = %v, want 2", got)
	}
	if got := agg.MemoryBytesByUser["root"]; got != float64(8*mib) {
		t.Errorf("MemoryBytesByUser[root] = %v, want %v — an unparseable row must be skipped, not zeroed",
			got, float64(8*mib))
	}
}

// TestParseActivityDetails_CapsCommandLabelSet pins the bound on the COMMAND label
// set. Past the cap a novel command folds into the fixed __other__ bucket and the
// fold is counted, so a saturated label set is visible instead of silent.
func TestParseActivityDetails_CapsCommandLabelSet(t *testing.T) {
	var rows []string
	for i := 0; i < activityCommandCap+10; i++ {
		rows = append(rows, fmt.Sprintf(
			`{"PID":"%d","USERNAME":"root","RES":"1M","WCPU":"1.00%%","COMMAND":"cmd%d"}`, i, i))
	}
	agg := parseActivityDetailsJSON(t, "["+strings.Join(rows, ",")+"]")

	if _, ok := agg.CPUPercentByCommand[activityOtherCommand]; !ok {
		t.Fatalf("expected an %s overflow bucket, got %d commands", activityOtherCommand, len(agg.CPUPercentByCommand))
	}
	if got := agg.CPUPercentByCommand[activityOtherCommand]; got != 10.0 {
		t.Errorf("%s CPU = %v, want 10 (ten folded rows at 1.00%% each)", activityOtherCommand, got)
	}
	stats := agg.Stats()
	if stats.Capped != 10 {
		t.Errorf("Stats().Capped = %d, want 10", stats.Capped)
	}
	if stats.MaxCommands != activityCommandCap {
		t.Errorf("Stats().MaxCommands = %d, want %d", stats.MaxCommands, activityCommandCap)
	}
	if stats.Commands != activityCommandCap+1 {
		t.Errorf("Stats().Commands = %d, want %d (the cap plus the overflow bucket)",
			stats.Commands, activityCommandCap+1)
	}
}

// TestFetchActivity_ParsesDetails pins that the aggregation is wired into the fetch —
// the whole point of #552 is that this payload is already fetched and was discarded.
func TestFetchActivity_ParsesDetails(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"headers":["849 threads:   13 running, 802 sleeping, 34 waiting"],"details":%s}`,
			activityDetailsFixture)
	})
	defer server.Close()

	data, err := client.FetchActivity()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := data.Processes.MemoryBytesByCommand["python3"], float64(512*mib); got != want {
		t.Errorf("MemoryBytesByCommand[python3] = %v, want %v", got, want)
	}
	if got, want := data.Processes.ThreadsByCommand["python3"], 4.0; got != want {
		t.Errorf("ThreadsByCommand[python3] = %v, want %v", got, want)
	}
}

// parseActivityDetailsJSON decodes a details array exactly as the client does — into
// []any — and aggregates it, so the test exercises the same decode path as a live
// response rather than a convenient typed shortcut.
func parseActivityDetailsJSON(t *testing.T, raw string) ProcessAggregate {
	t.Helper()
	var rows []any
	if err := json.Unmarshal([]byte(raw), &rows); err != nil {
		t.Fatalf("fixture is not valid JSON: %v", err)
	}
	return parseActivityDetails(rows)
}
