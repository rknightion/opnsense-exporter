package main

import (
	"encoding/json"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestModulePathMatchesReleaseVersion guards a release failure this repo has not
// hit yet only because it never had a compliant module path to lose.
//
// Go's semantic-import-versioning requires a module released at v2+ to have a
// module path ending /vN. release-please does NOT maintain that — it updates the
// manifest and the changelog and nothing else — so a major bump silently leaves
// go.mod behind, and the tag then names a version the path does not carry.
// tailscale2otel shipped exactly that twice (its #174 and #244): at v2.0.0 the
// image, chart and notices published while the archives, checksums, signatures
// and SBOMs did not, and re-running could not fix it because the damage was in
// the tag itself.
//
// This repo ran v1 through v3 on an unsuffixed path, which is the same latent
// defect; the opnsense2otel rename was the moment to land /v4 and this guard
// with it.
//
// The timing is what makes it catchable. .release-please-manifest.json is bumped
// BY THE RELEASE PR, so on that branch the manifest already reads the new major
// while go.mod still reads the old one — this fails there, on the one PR that
// must not merge unnoticed, rather than after the tag is cut.
//
// Fix with: scripts/bump-module-major.sh
func TestModulePathMatchesReleaseVersion(t *testing.T) {
	raw, err := os.ReadFile(".release-please-manifest.json")
	if err != nil {
		t.Fatalf("read release-please manifest: %v", err)
	}
	var manifest map[string]string
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("parse release-please manifest: %v", err)
	}
	version, ok := manifest["."]
	if !ok {
		t.Fatalf("release-please manifest has no root (\".\") entry: %v", manifest)
	}
	releaseMajor, err := strconv.Atoi(strings.SplitN(version, ".", 2)[0])
	if err != nil {
		t.Fatalf("parse major from manifest version %q: %v", version, err)
	}

	modPath := modulePath(t, "go.mod")
	moduleMajor := majorOfModulePath(modPath)

	// Three states are legitimate, and only the first is dangerous to miss.
	//
	//   module < release    — the failure above. The manifest has been bumped (that is
	//                         what the release PR does) and go.mod has not, so the tag
	//                         about to be cut will not match the path. FAIL.
	//   module == release   — steady state on main between majors.
	//   module == release+1 — the pre-bump. The path has to move BEFORE the release
	//                         commit is tagged, so main leads the last released version
	//                         by one major until that release lands. This is the state
	//                         the rename created: path /v4, last release 3.0.0.
	//
	// Anything further ahead is an overshoot: a path claiming a major nothing is
	// heading toward, which breaks the eventual tag just as badly.
	switch {
	case moduleMajor < releaseMajor:
		t.Fatalf(`module path major is BEHIND the release version.

  go.mod module path: %s  (major v%d)
  release version:    %s  (major v%d)

Go requires a v2+ module's path to end in /vN, and release-please does not
maintain that. Tagging v%s against this path breaks the release build.

Fix it before the release PR merges:

    scripts/bump-module-major.sh %d`,
			modPath, moduleMajor, version, releaseMajor, version, releaseMajor)
	case moduleMajor > releaseMajor+1:
		t.Fatalf(`module path major is more than one ahead of the release version.

  go.mod module path: %s  (major v%d)
  release version:    %s  (major v%d)

One ahead is the legitimate pre-bump (the path must move before the major release
is tagged). More than one means the path claims a major nothing is heading toward,
which breaks the eventual tag the same way being behind does.`,
			modPath, moduleMajor, version, releaseMajor)
	}

	// The tool modules nest under the root path. A stale suffix there fails the
	// build only when that module is exercised, which is a separate CI lane, so
	// check it from here where it is cheap.
	for _, tool := range []string{"promqlcheck"} {
		gomod := "tools/" + tool + "/go.mod"
		if _, err := os.Stat(gomod); err != nil {
			continue
		}
		if got, want := modulePath(t, gomod), modPath+"/tools/"+tool; got != want {
			t.Errorf("tools/%s module path = %q, want %q", tool, got, want)
		}
	}
}

// modulePath returns the module path declared by a go.mod.
func modulePath(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	m := regexp.MustCompile(`(?m)^module\s+(\S+)`).FindStringSubmatch(string(body))
	if m == nil {
		t.Fatalf("%s declares no module path", path)
	}
	return m[1]
}

// majorOfModulePath extracts the major version a module path encodes. A path with
// no /vN suffix is v1 (and v0, which shares the unsuffixed form — the distinction
// does not matter here, since neither may carry a suffix).
func majorOfModulePath(path string) int {
	m := regexp.MustCompile(`/v(\d+)$`).FindStringSubmatch(path)
	if m == nil {
		return 1
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 1
	}
	return n
}
