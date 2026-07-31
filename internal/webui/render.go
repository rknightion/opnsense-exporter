package webui

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"strings"

	"github.com/rknightion/opnsense2otel/v4/internal/geoip"
	"github.com/rknightion/opnsense2otel/v4/internal/options"
)

//go:embed templates/page.html.tmpl
var templatesFS embed.FS

// funcMap is used by the single-page console template for first-paint rendering
// (the JS mirrors these helpers for its live-refresh rebuild).
var funcMap = template.FuncMap{
	"geoipCredit":   geoipCredit,
	"sparkline":     sparkline,
	"outcomeStrip":  outcomeStrip,
	"healthClass":   healthClass,
	"stateClass":    stateClass,
	"freshClass":    freshClass,
	"upstreamClass": upstreamClass,
	"captureClass":  captureClass,
	"pct":           pct,
}

// pageTmpl is the one console template, parsed once at init. A malformed
// template panics here (caught by any test importing this package), never at
// request time.
var pageTmpl = template.Must(template.New("page.html.tmpl").Funcs(funcMap).ParseFS(templatesFS, "templates/page.html.tmpl"))

// view is the root value passed to the single-page console template. Data is the
// poll-refreshed status snapshot; Config is the static, server-rendered
// effective config (never re-fetched by the poll — EffectiveConfig reads secret
// files from disk). RefreshMs is the client poll interval in milliseconds.
type view struct {
	Title          string
	RefreshMs      int
	Data           Status
	Config         []options.ConfigSection
	DisableConfig  bool
	DisableDevices bool
}

// renderPage renders the single console page from the pre-parsed template.
func renderPage(w io.Writer, v view) error {
	return pageTmpl.Execute(w, v)
}

// geoipCredit renders the CC BY 4.0 attribution for the bundled DB-IP Lite
// databases into the console footer (#549).
//
// It is unconditional and it is a template FUNC rather than a view field on
// purpose. Unconditional because the console cannot know which database answered
// a lookup — an operator may have pointed the flags at MaxMind — and a credit
// that appears only sometimes is one that is missing sometimes; crediting DB-IP
// on an image that ships their data is correct whatever else is also loaded. A
// func because it needs no state from the request, so no handler, no Deps field
// and no wiring in main can accidentally drop it.
//
// Built from the geoip constants, never from a literal typed here, so the console
// and the image's /licenses copy cannot drift apart.
func geoipCredit() template.HTML {
	return template.HTML(fmt.Sprintf(
		`IP geolocation data by <a href="%s" rel="noopener noreferrer">%s</a> (<a href="%s" rel="noopener noreferrer">%s</a>)`,
		template.HTMLEscapeString(geoip.BundledProviderURL),
		template.HTMLEscapeString(geoip.BundledProvider),
		template.HTMLEscapeString(geoip.BundledLicenseURL),
		template.HTMLEscapeString(geoip.BundledLicense)))
}

// freshClass maps a collector freshness state to a badge modifier class.
func freshClass(state string) string {
	switch state {
	case "fresh":
		return "ok"
	case "stale":
		return "warn"
	default:
		return "pending"
	}
}

// upstreamClass maps an UpstreamHealth.State to a badge modifier class. Both
// failure states are "bad": a box that answers with an error is no more usable
// than one that does not answer at all, even though the two are worded
// differently.
func upstreamClass(state string) string {
	switch state {
	case "ok":
		return "ok"
	case "unreachable", "error":
		return "bad"
	default: // pending, unknown
		return "pending"
	}
}

// captureClass maps a CaptureInfo.State to a badge modifier class. A partial
// capture is a warning, not a failure: the data shown IS current, it just arrived
// with a gather error alongside it.
func captureClass(state string) string {
	switch state {
	case "full":
		return "ok"
	case "partial":
		return "warn"
	default: // never
		return "pending"
	}
}

// sparkline renders a compact SVG polyline of durations. Fewer than two points
// yields an empty string (nothing to draw).
func sparkline(vals []float64) template.HTML {
	if len(vals) < 2 {
		return ""
	}
	const w, h = 120.0, 24.0
	minV, maxV := vals[0], vals[0]
	for _, v := range vals {
		if v < minV {
			minV = v
		}
		if v > maxV {
			maxV = v
		}
	}
	span := maxV - minV
	if span == 0 {
		span = 1
	}
	var b strings.Builder
	step := w / float64(len(vals)-1)
	for i, v := range vals {
		x := float64(i) * step
		y := h - ((v-minV)/span)*h
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%.1f,%.1f", x, y)
	}
	return template.HTML(fmt.Sprintf(
		`<svg class="spark" viewBox="0 0 %g %g" preserveAspectRatio="none" role="img" aria-label="run durations"><polyline points="%s"/></svg>`,
		w, h, b.String()))
}

// outcomeStrip renders the pass/fail history as a row of small cells, oldest to
// newest. Empty history yields an empty string.
func outcomeStrip(outcomes []bool) template.HTML {
	if len(outcomes) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(`<span class="outcomes" role="img" aria-label="recent run outcomes">`)
	for _, ok := range outcomes {
		cls := "bad"
		if ok {
			cls = "ok"
		}
		fmt.Fprintf(&b, `<i class="cell %s"></i>`, cls)
	}
	b.WriteString(`</span>`)
	return template.HTML(b.String())
}

// healthClass maps a health verdict to a CSS modifier class.
func healthClass(health string) string {
	switch health {
	case "healthy":
		return "ok"
	case "degraded":
		return "bad"
	default:
		return "warn"
	}
}

// stateClass maps a collector row state to a CSS modifier class.
func stateClass(state string) string {
	switch state {
	case "ok":
		return "ok"
	case "failing":
		return "bad"
	default:
		return "warn"
	}
}

// pct renders a success-rate percentage; -1 (never run) shows as an em dash.
func pct(v float64) string {
	if v < 0 {
		return "—"
	}
	return fmt.Sprintf("%.0f%%", v)
}
