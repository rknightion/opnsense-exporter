---
id: OPN-0001
title: Rare data race in syslog Listener shutdown (Close vs the TLS accept goroutine)
status: In Progress
assignee:
  - '@claude'
created_date: '2026-08-14 14:06'
updated_date: '2026-08-21 19:03'
labels:
  - bug
  - 'area:logship'
  - flaky-ci
dependencies: []
references:
  - 'https://github.com/rknightion/opnsense2otel/issues/655'
ordinal: 1000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Migrated from GitHub issue #655 (opened 2026-08-05, closed on migration 2026-08-14). Nothing has been
dropped; the reproduction evidence below is the expensive part.

## The trace

The `Race detector` job failed on #652's CI run (job 92398992886, 2026-08-05 18:08 UTC). #652 only
bumps `step-security/harden-runner`, so this is **pre-existing on `main`**, not caused by that PR.

```
WARNING: DATA RACE
Write at 0x00c000204f68 by goroutine 1084:
  sync.(*Once).doSlow()
      /opt/hostedtoolcache/go/1.26.5/x64/src/sync/once.go:78 +0xa1
  ...syslog.(*Listener).Run.func1()
      internal/logship/syslog/listener.go:268 +0x176

Previous read at 0x00c000204f68 by goroutine 1085:
  ...syslog.(*Listener).Run.func4()
      internal/logship/syslog/listener.go:284 +0x7b

Goroutine 1084 (running) created at:
  ...syslog.(*Listener).Run()  internal/logship/syslog/listener.go:264 +0x124
  ...TestListenerTLSShutdownCancellationDoesNotCountRejection.func2()
      internal/logship/syslog/listener_tls_test.go:483 +0x9c

Goroutine 1085 (running) created at:
  ...syslog.(*Listener).Run()  internal/logship/syslog/listener.go:284 +0x3f9
  ...TestListenerTLSShutdownCancellationDoesNotCountRejection.func2()
      internal/logship/syslog/listener_tls_test.go:483 +0x9c

--- FAIL: TestListenerTLSShutdownCancellationDoesNotCountRejection (0.00s)
    testing.go:1712: race detected during execution of test
```

Both goroutines belong to the **same** `Run` call: `func1` is the ctx watchdog (`listener.go:268` =
`_ = l.Close()`), `func4` is the TLS accept goroutine. `f()` is inlined into `doSlow`, so the
instrumented write is inside `Close`'s `once.Do` closure body.

## Not reproduced — read this before assuming it is easy

**~290 runs across two platforms, zero races.**

| configuration | runs | result |
|---|---|---|
| darwin/arm64, whole package, `-race -count=30 -cpu=1,2,4,8` | 120 | clean |
| darwin/arm64, `-race -count=150 -run TestListenerTLS` | 150 | clean |
| linux/amd64 native (camden, 24 cores), whole suite `go test -race -count=1 ./...`, `GORACE="halt_on_error=1 history_size=7"`, commit `8928d155` | 20 | clean |

`main`'s own CI is green on 18 of the last 20 runs, so it is rare there too.

**What the amd64 run eliminated.** The most plausible remaining hypothesis was that the failure needs
amd64 *plus* whole-suite scheduling pressure rather than a single-package run. It does not, at least
not at this rate — 20 consecutive whole-suite runs on a 24-core amd64 box is a materially harder test
than 150 single-package runs, and it is still clean. Whatever the trigger is, it is rarer than
1-in-20 whole-suite runs on the platform that produced it.

**Static reading has failed twice.** Every `Listener` field the two goroutines share is either
channel-synchronised (`closing`, `tcpSem`/`tlsSem`), mutex-guarded (`closeCh` under `closeMu`,
`refusalLast` under `refusalMu`), or immutable after `NewListener`. The reported read offset sits in
`Run.func4`, a closure whose only body is `defer wg.Done(); l.serveTLS()` — and `serveTLS` is far too
large to inline, so what is actually read at `+0x7b` is not obvious from source.

## Impact

Shutdown-path only, and `Close` is `sync.Once`-guarded, so the observable behaviour (sockets closed,
connection goroutines waited on) is not obviously wrong. The cost today is a flaky required check
that blocks unrelated PRs — #652 went green on a plain re-run with no code change.

## Standing constraint

**Do not accept a fix that cannot demonstrate the race first.** An unfalsifiable fix here is worse
than the flake: it would close the task while leaving the real defect in place and removing the only
signal that it exists.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Race reproduced deterministically, or under a documented flag/platform/timing combination
- [ ] #2 Root cause identified: the exact field, and which of the two accesses is unsynchronised
- [ ] #3 Fix verified by the reproduction failing before it and passing after it
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 make lint
- [ ] #2 make test
- [ ] #3 make check-public-ips
- [ ] #4 make docs-check
- [ ] #5 make grafana-check
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Disassemble Run.func4/doSlow on amd64: +0x7b and +0xa1 are CALL sites (serveTLS, once.Do's f), so the CI trace's top frames were elided — the racing accesses live inside serveTLS and Close, not in the two closures.
2. Root cause: sync.WaitGroup's own race annotations (race.Write(&wg.sema) in Wait, race.Read(&wg.sema) in Add on the 0->1 transition) — l.conns.Wait() in Close vs l.conns.Add(1) in the accept loops.
3. Reproduce with a stress test that cancels the context on a 5us-stepped sweep across the accept path.
4. Fix: connMu orders close(l.closing) against a conns.Add via trackConn(); accept loops drop the connection when it reports closing.
5. Verify: repro fails pre-fix, 20k iterations clean post-fix; keep a 200-iteration regression test.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
## Untried, in value order

1. **Disassemble `Run.func4` on amd64 and identify what is read at `+0x7b`.** The only line of attack
   that does not depend on catching a rare interleaving, and the highest-value next step. Static
   source reading has already failed twice, and `serveTLS` is too large to inline, so the read is not
   derivable from the source.
2. Drive the shutdown path directly under a scheduler-perturbing harness rather than re-running the
   test suite and hoping.

## Do not spend budget on

Re-running the configurations in the table in the description. That is ~290 runs of evidence that the
naive approaches do not reproduce it. Anything that is "run it more times" needs a reason why this
attempt differs.

## Currency

The amd64 result was taken at `8928d155`. `main` has moved since (#664-#669 and everything after),
but none of those commits touch `listener.go` or the TLS accept path, so the negative result still
stands. Re-check that claim before relying on it if `internal/logship/syslog/` has changed.
<!-- SECTION:NOTES:END -->
