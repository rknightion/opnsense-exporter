package webui

import (
	"bytes"
	"embed"
	"net/http"
	"strings"
	"time"
)

// fontFiles is the self-hosted console font bundle. The handler serves only
// the fixed filenames accepted by Font, so a request path cannot select an
// arbitrary embedded file.
//
//go:embed fonts/*.woff2
var fontFiles embed.FS

// Font returns one self-hosted console font by its public filename. The caller
// owns HTTP policy; this package owns the embedded bytes and the filename
// allowlist used by the console.
func Font(name string) ([]byte, bool) {
	switch name {
	case "hanken-grotesk-latin.woff2", "hanken-grotesk-latin-ext.woff2", "JetBrainsMono-Variable.woff2":
		data, err := fontFiles.ReadFile("fonts/" + name)
		return data, err == nil
	default:
		return nil, false
	}
}

const consoleFontPrefix = "/_static/fonts/"

func init() { registerRoutes((*Server).registerConsoleFonts) }

// registerConsoleFonts mounts the self-hosted console fonts. They contain no
// operator or tailnet data and are intentionally available without any page
// request state.
func (s *Server) registerConsoleFonts(mux *http.ServeMux) {
	mux.HandleFunc("GET /_static/fonts/", s.handleConsoleFont)
}

// handleConsoleFont serves the three fixed embedded font files used by the
// console. Font performs the filename allowlist; request paths can never
// select another embedded or repository file.
func (s *Server) handleConsoleFont(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, consoleFontPrefix)
	font, ok := Font(name)
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "font/woff2")
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(font))
}
