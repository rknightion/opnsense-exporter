package webui

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"strings"
)

//go:embed templates/*.tmpl
var templatesFS embed.FS

//go:embed static/app.css static/app.js
var staticFS embed.FS

// funcMap is shared by every page template.
var funcMap = template.FuncMap{
	"sparkline":    sparkline,
	"outcomeStrip": outcomeStrip,
	"healthClass":  healthClass,
	"stateClass":   stateClass,
	"pct":          pct,
}

// navItem is one entry in the console's top navigation. Active marks the
// current page. The nav is data-driven (see Server.nav) so disabled pages are
// simply omitted from the slice.
type navItem struct {
	Label, Href, Key string
	Active           bool
}

// view is the root value passed to every page render: the shared shell (title,
// page id, nav, refresh interval) plus the page-specific payload in Data. Every
// page template accesses .Data for its own model and the shell fields for the
// chrome, so a new page lane needs no changes to the layout.
type view struct {
	Title          string
	PageID         string
	Nav            []navItem
	RefreshSeconds int
	Data           any
}

// renderPage renders one page template composed with the shared layout. It
// parses the layout and the named page template into a fresh set per call, so
// each page's `{{define "body"}}` block is unambiguous. New page lanes call
// this with their own template filename and a view built via Server.newView.
func renderPage(w io.Writer, page string, v view) error {
	t, err := template.New("layout.html.tmpl").Funcs(funcMap).
		ParseFS(templatesFS, "templates/layout.html.tmpl", "templates/"+page)
	if err != nil {
		return err
	}
	return t.ExecuteTemplate(w, "layout.html.tmpl", v)
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
