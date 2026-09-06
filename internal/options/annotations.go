package options

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/alecthomas/kingpin/v2"

	"github.com/rknightion/opnsense2otel/v5/internal/annotations"
)

var (
	annotationsEnabled = kingpin.Flag(
		"annotations.enabled",
		"Write OPNsense change events (reboots, configuration changes, interface counter "+
			"resets, upgrades, certificate renewals, feed updates) into Grafana's annotation "+
			"store so they overlay any dashboard. Off by default: this is the exporter's only "+
			"outbound write.",
	).Envar("OPN2OTEL_ANNOTATIONS_ENABLED").Default("false").Bool()
	annotationsGrafanaURL = kingpin.Flag(
		"annotations.grafana-url",
		"Grafana base URL to write annotations to, e.g. https://mystack.grafana.net.",
	).Envar("OPN2OTEL_ANNOTATIONS_GRAFANA_URL").Default("").String()
	annotationsToken = kingpin.Flag(
		"annotations.token",
		"Grafana service-account token used to write annotations. It needs the annotation "+
			"write permission and nothing else. This flag/ENV or "+
			"OPN2OTEL_ANNOTATIONS_TOKEN_FILE may be set.",
	).Envar("OPN2OTEL_ANNOTATIONS_TOKEN").Default("").String()
	annotationsInterval = kingpin.Flag(
		"annotations.interval",
		"How often the watched event metrics are checked for changes. This bounds how late "+
			"an annotation is WRITTEN, never where it is PLACED — each annotation carries the "+
			"event's own timestamp.",
	).Envar("OPN2OTEL_ANNOTATIONS_INTERVAL").Default("60s").Duration()
	annotationsLookback = kingpin.Flag(
		"annotations.lookback",
		"How old an event may be and still be worth annotating, and how far back the "+
			"startup reconciliation looks for annotations this exporter already wrote. Keeps a "+
			"fresh deployment from annotating a reboot that happened months ago. Read this "+
			"together with --annotations.max-per-cycle: a fresh deployment finds every event "+
			"inside this window at once, and that first-run backlog drains at most "+
			"max-per-cycle annotations per --annotations.interval (default 20/60s), so a 24h "+
			"lookback on a busy firewall takes several minutes to catch up. Shorten this if "+
			"you want a fresh deployment to start clean rather than backfill a day.",
	).Envar("OPN2OTEL_ANNOTATIONS_LOOKBACK").Default("24h").Duration()
	annotationsTimeout = kingpin.Flag(
		"annotations.timeout",
		"Timeout for each Grafana annotation API request.",
	).Envar("OPN2OTEL_ANNOTATIONS_TIMEOUT").Default("10s").Duration()
	annotationsExtraTags = kingpin.Flag(
		"annotations.extra-tags",
		"Extra tag to add to every written annotation (repeatable), e.g. env:prod. Every "+
			"annotation already carries opnsense2otel, the event kind and instance:<name>.",
	).Envar("OPN2OTEL_ANNOTATIONS_EXTRA_TAGS").Strings()
	annotationsKinds = kingpin.Flag(
		"annotations.kinds",
		"Event kind to write, repeatable (comma-separated in the environment variable). "+
			"When set this is the EXACT set written, overriding the defaults in both "+
			"directions. Unset writes every kind except the default-off ones, which are "+
			"excluded for their cadence rather than their importance: "+
			strings.Join(annotations.DefaultOffKinds(), ", ")+". Known kinds: "+
			strings.Join(annotations.KnownKinds(), ", ")+".",
	).Envar("OPN2OTEL_ANNOTATIONS_KINDS").Strings()
	annotationsMaxPerCycle = kingpin.Flag(
		"annotations.max-per-cycle",
		"Maximum annotation posts ATTEMPTED per check, successful or not. A guard "+
			"against one bad reading writing hundreds of annotations, not a rate limit to "+
			"tune. It also paces the first-run backlog --annotations.lookback produces: "+
			"the excess is not marked seen, so it is re-proposed on the next check and a "+
			"deployment with a 24h lookback drains at this many per --annotations.interval "+
			"until it is caught up. Events are only lost if they age out of the lookback "+
			"before the backlog reaches them. Raising it drains faster but makes a rate limit "+
			"(opnsense_exporter_annotations_rate_limited_total) more likely, since a "+
			"Grafana org shares one annotation limit across every writer.",
	).Envar("OPN2OTEL_ANNOTATIONS_MAX_PER_CYCLE").Default("20").Int()
)

// AnnotationsConfig holds the resolved annotation-writer configuration.
type AnnotationsConfig struct {
	GrafanaURL  string
	Token       string
	Interval    time.Duration
	Lookback    time.Duration
	Timeout     time.Duration
	ExtraTags   []string
	Kinds       []string
	MaxPerCycle int
}

// Validate rejects a configuration that would start cleanly and then fail on every
// write. The URL check is deliberately strict for the reason recorded in
// PyroscopeConfig.Validate: a schemeless "host:3000" parses without error and only
// fails at request time, once per interval, forever.
func (c *AnnotationsConfig) Validate() error {
	if c.GrafanaURL == "" {
		return fmt.Errorf("annotations.grafana-url must be set when annotations are enabled")
	}
	parsed, err := url.Parse(c.GrafanaURL)
	if err != nil {
		return fmt.Errorf("annotations.grafana-url %q is not a valid URL: %w", c.GrafanaURL, err)
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return fmt.Errorf("annotations.grafana-url %q must be a full http(s) URL, e.g. "+
			"https://mystack.grafana.net (got scheme %q, host %q)",
			c.GrafanaURL, parsed.Scheme, parsed.Host)
	}
	if c.Token == "" {
		return fmt.Errorf("annotations.token (or OPN2OTEL_ANNOTATIONS_TOKEN_FILE) " +
			"must be set when annotations are enabled")
	}
	if c.Interval <= 0 {
		return fmt.Errorf("annotations.interval must be positive, got %s", c.Interval)
	}
	if c.Lookback <= 0 {
		return fmt.Errorf("annotations.lookback must be positive, got %s", c.Lookback)
	}
	if c.Timeout <= 0 {
		return fmt.Errorf("annotations.timeout must be positive, got %s", c.Timeout)
	}
	if c.MaxPerCycle <= 0 {
		return fmt.Errorf("annotations.max-per-cycle must be positive, got %d", c.MaxPerCycle)
	}
	for _, tag := range c.ExtraTags {
		if strings.TrimSpace(tag) == "" {
			return fmt.Errorf("annotations.extra-tags contains an empty tag")
		}
	}
	// A typo here has no symptom at runtime — the kind simply never matches a
	// watch, so the exporter writes nothing for it and looks healthy doing so.
	known := map[string]bool{}
	for _, kind := range annotations.KnownKinds() {
		known[kind] = true
	}
	for _, kind := range c.Kinds {
		if !known[kind] {
			return fmt.Errorf("annotations.kinds contains unknown event kind %q; known kinds are %s",
				kind, strings.Join(annotations.KnownKinds(), ", "))
		}
	}
	return nil
}

// Annotations assembles the annotation-writer configuration. The returned bool
// reports whether writing is enabled; when it is, the config has been validated.
func Annotations() (*AnnotationsConfig, bool, error) {
	if !*annotationsEnabled {
		return nil, false, nil
	}

	token, err := resolveSecret("OPN2OTEL_ANNOTATIONS_TOKEN_FILE", *annotationsToken)
	if err != nil {
		return nil, false, err
	}

	tags := make([]string, 0, len(*annotationsExtraTags))
	for _, tag := range *annotationsExtraTags {
		tags = append(tags, strings.TrimSpace(tag))
	}

	kinds := make([]string, 0, len(*annotationsKinds))
	for _, kind := range *annotationsKinds {
		if trimmed := strings.TrimSpace(kind); trimmed != "" {
			kinds = append(kinds, trimmed)
		}
	}

	cfg := &AnnotationsConfig{
		GrafanaURL:  strings.TrimSpace(*annotationsGrafanaURL),
		Token:       strings.TrimSpace(token),
		Interval:    *annotationsInterval,
		Lookback:    *annotationsLookback,
		Timeout:     *annotationsTimeout,
		ExtraTags:   tags,
		Kinds:       kinds,
		MaxPerCycle: *annotationsMaxPerCycle,
	}
	if err := cfg.Validate(); err != nil {
		return nil, false, err
	}
	return cfg, true, nil
}
