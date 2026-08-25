package secureio

import (
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadAllLimitedRejectsLimitPlusOne(t *testing.T) {
	got, err := ReadAllLimited(strings.NewReader("12345"), 4)
	if !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("error = %v, want ErrBodyTooLarge", err)
	}
	if got != nil {
		t.Fatalf("body = %q, want nil", got)
	}

	got, err = ReadAllLimited(strings.NewReader("1234"), 4)
	if err != nil || string(got) != "1234" {
		t.Fatalf("body = %q, error = %v", got, err)
	}
}

func TestReadAllLimitedMaximumDoesNotOverflow(t *testing.T) {
	got, err := ReadAllLimited(strings.NewReader("body"), math.MaxInt64)
	if err != nil || string(got) != "body" {
		t.Fatalf("body = %q, error = %v", got, err)
	}
}

func TestWritePrivateFileTightensDirectoryAndFileModes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "captures")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "response.json")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WritePrivateFile(path, []byte("new")); err != nil {
		t.Fatal(err)
	}
	for target, want := range map[string]os.FileMode{dir: 0o700, path: 0o600} {
		info, err := os.Stat(target)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Errorf("%s mode = %o, want %o", target, got, want)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "new" {
		t.Fatalf("contents = %q, error = %v", got, err)
	}
}

func TestWritePrivateFileDirectorySwapCannotRedirectWrite(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "captures")
	moved := filepath.Join(parent, "original")
	victim := filepath.Join(parent, "victim")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(victim, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "response.json")
	err := writePrivateFile(path, []byte("private"), func() {
		if renameErr := os.Rename(dir, moved); renameErr != nil {
			t.Fatal(renameErr)
		}
		if symlinkErr := os.Symlink(victim, dir); symlinkErr != nil {
			t.Fatal(symlinkErr)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(victim, "response.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("swapped-in directory received capture: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(moved, "response.json"))
	if err != nil || string(got) != "private" {
		t.Fatalf("trusted directory contents = %q, error = %v", got, err)
	}
}

func TestReadAllLimitedPropagatesReaderError(t *testing.T) {
	want := errors.New("read failed")
	_, err := ReadAllLimited(errorReader{err: want}, 4)
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }

var _ io.Reader = errorReader{}
