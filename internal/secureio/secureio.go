// Package secureio provides bounded reads and private atomic writes for tools
// that handle live firewall response data.
package secureio

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
)

const MaxAPIResponseBytes int64 = 64 << 20

var ErrBodyTooLarge = errors.New("response body exceeds limit")

func ReadAllLimited(r io.Reader, limit int64) ([]byte, error) {
	if limit < 0 {
		return nil, fmt.Errorf("invalid response body limit %d", limit)
	}
	reader := r
	if limit < math.MaxInt64 {
		reader = io.LimitReader(r, limit+1)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("%w (%d bytes)", ErrBodyTooLarge, limit)
	}
	return body, nil
}

// WritePrivateFile creates the parent directory with mode 0700, tightens an
// existing directory, and atomically replaces path with a 0600 regular file.
func WritePrivateFile(path string, data []byte) error {
	return writePrivateFile(path, data, nil)
}

func writePrivateFile(path string, data []byte, afterRootOpen func()) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create private directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("inspect private directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("private directory %q is not a directory", dir)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("open private directory: %w", err)
	}
	defer root.Close()
	handleInfo, err := root.Stat(".")
	if err != nil {
		return fmt.Errorf("inspect opened private directory: %w", err)
	}
	// The directory may have been exchanged between Lstat and OpenRoot. Require
	// the opened handle to identify the object that was validated; all subsequent
	// file operations stay relative to this handle, so later path swaps cannot
	// redirect captures into another directory.
	if !os.SameFile(info, handleInfo) {
		return fmt.Errorf("private directory %q changed while opening", dir)
	}
	if err := root.Chmod(".", 0o700); err != nil {
		return fmt.Errorf("tighten private directory: %w", err)
	}
	if afterRootOpen != nil {
		afterRootOpen()
	}

	tmpName, tmp, err := createPrivateTemp(root, filepath.Base(path))
	if err != nil {
		return fmt.Errorf("create temporary capture: %w", err)
	}
	removeTmp := true
	defer func() {
		if removeTmp {
			_ = root.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("set temporary capture mode: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temporary capture: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary capture: %w", err)
	}
	if err := root.Rename(tmpName, filepath.Base(path)); err != nil {
		return fmt.Errorf("replace capture: %w", err)
	}
	removeTmp = false
	return nil
}

func createPrivateTemp(root *os.Root, base string) (string, *os.File, error) {
	for range 100 {
		var random [8]byte
		if _, err := rand.Read(random[:]); err != nil {
			return "", nil, err
		}
		name := "." + base + "." + hex.EncodeToString(random[:]) + ".tmp"
		f, err := root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			return name, f, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return "", nil, err
		}
	}
	return "", nil, fmt.Errorf("temporary capture name collision limit reached")
}
