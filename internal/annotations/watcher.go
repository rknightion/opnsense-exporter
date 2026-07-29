package annotations

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// instanceLabel is the appliance identity every collector metric carries. It is
// tagged on every annotation, because an annotation with no instance tag is
// unusable the moment a second firewall is monitored.
const instanceLabel = "opnsense_instance"

// futureTolerance is how far ahead of the exporter's clock an event instant may sit
// before it is refused. OPNsense renders its timestamps with a zone abbreviation
// the exporter cannot always resolve, so a small skew is normal; a large one means
// something is wrong and an annotation dated next week would be invisible on every
// dashboard until then.
const futureTolerance = 5 * time.Minute

// Watcher diffs the watched instant-valued metrics and writes an annotation for
// each change.
type Watcher struct {
	cfg      Config
	gatherer prometheus.Gatherer
	client   *client
	log      *slog.Logger
	metrics  *selfMetrics

	// seen is the dedupe set, keyed by series identity AND instant, so an event
	// is written once while a value that flaps between two instants still
	// produces one annotation per distinct instant. Values are the instant, so
	// entries can be pruned once they fall out of the lookback window — safe
	// because detect() refuses an instant that old, so a pruned entry can never
	// be proposed again. Without the prune this map grows for the life of the
	// process.
	seen map[string]int64
	// reconciled records whether the startup read-back against Grafana succeeded.
	// It did not, on a Grafana outage — and in that case the first pass seeds
	// silently instead of posting, because duplicating the whole recent timeline
	// is a worse failure than missing one event.
	reconciled bool
	seeded     bool
	now        func() time.Time
}

// New returns a Watcher over the given gatherer. The gatherer is the same registry
// `/metrics` replays, so detection makes no OPNsense API call of its own — it reads
// the snapshot the poll scheduler already filled.
func New(cfg Config, gatherer prometheus.Gatherer, registerer prometheus.Registerer, log *slog.Logger) *Watcher {
	return &Watcher{
		cfg:      cfg,
		gatherer: gatherer,
		client:   newClient(cfg),
		log:      log,
		metrics:  newSelfMetrics(registerer),
		seen:     map[string]int64{},
		now:      time.Now,
	}
}

// Run reconciles against Grafana once, then diffs on every tick until ctx is done.
func (w *Watcher) Run(ctx context.Context) {
	w.reconcile(ctx)

	ticker := time.NewTicker(w.cfg.Interval)
	defer ticker.Stop()
	for {
		w.tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// reconcile seeds the dedupe set from annotations already in Grafana.
func (w *Watcher) reconcile(ctx context.Context) {
	found, err := w.client.existing(ctx, w.now())
	if err != nil {
		w.log.Warn("annotation reconciliation failed; the first pass will seed silently "+
			"rather than risk duplicating the recent timeline", "err", err)
		return
	}
	for _, annotation := range found {
		kind, instance, detail := decodeTags(annotation.Tags)
		if kind == "" {
			continue
		}
		w.seen[dedupeKey(kind, instance, detail, annotation.Time)] = annotation.Time
	}
	w.reconciled = true
	w.log.Debug("annotation reconciliation complete",
		"existing", len(found), "lookback", w.cfg.Lookback.String())
}

// tick performs one detection pass.
func (w *Watcher) tick(ctx context.Context) {
	w.prune(w.now())

	events, err := w.detect()
	if err != nil {
		w.log.Warn("annotation detection failed", "err", err)
		return
	}

	// The first pass after a failed reconciliation is a silent seed: every watched
	// series looks new to an empty dedupe set, and posting them all would write an
	// annotation for a reboot that happened months ago.
	if !w.seeded {
		w.seeded = true
		if !w.reconciled {
			w.log.Info("annotation baseline seeded without posting",
				"events", len(events),
				"reason", "startup reconciliation against Grafana did not succeed")
			return
		}
	}

	// The cap counts ATTEMPTS, not successes. Counting successes means it never
	// trips while Grafana is rejecting, so a 429 - which says "you are sending too
	// many requests" - is answered by sending the entire backlog again on the next
	// tick, forever, sustaining the condition that caused it (#519).
	attempted := 0
	failures := 0
	for _, event := range events {
		if attempted >= w.cfg.MaxPerCycle {
			w.metrics.skipped.Add(float64(len(events) - attempted))
			w.log.Warn("annotation cycle cap reached; remaining events skipped",
				"cap", w.cfg.MaxPerCycle, "skipped", len(events)-attempted)
			break
		}
		attempted++
		if err := w.client.post(ctx, event); err != nil {
			w.metrics.failed.Inc()
			failures++
			// One line per cycle, not one per event: a rate-limited exporter at the
			// cap would otherwise log MaxPerCycle identical warnings every interval.
			if failures == 1 {
				w.log.Warn("annotation post failed", "kind", event.Kind, "err", err)
			}
			// NOT marked seen: an unwritten annotation must be retried, or a
			// transient Grafana error would silently lose the event for good.
			continue
		}
		w.markSeen(event)
		w.metrics.posted.Inc()
		w.metrics.lastSuccess.Set(float64(w.now().Unix()))
		w.log.Debug("annotation written", "kind", event.Kind, "at", event.At.UTC().Format(time.RFC3339))
	}
	if failures > 1 {
		w.log.Warn("further annotation posts failed this cycle", "failures", failures,
			"cap", w.cfg.MaxPerCycle)
	}
}

// detect gathers the registry and returns the events not yet seen.
func (w *Watcher) detect() ([]Event, error) {
	families, err := w.gatherer.Gather()
	if err != nil {
		// A partial gather still carries usable families; Gather's contract is that
		// err and metrics can both be non-nil. Only a total failure is fatal here.
		if len(families) == 0 {
			return nil, err
		}
		w.log.Debug("partial gather while detecting annotations", "err", err)
	}

	byName := make(map[string]*dto.MetricFamily, len(families))
	for _, family := range families {
		byName[family.GetName()] = family
	}

	now := w.now()
	oldest := now.Add(-w.cfg.Lookback)
	newest := now.Add(futureTolerance)

	var events []Event
	for _, watch := range Watches {
		family, ok := byName[watch.Metric]
		if !ok {
			continue
		}
		offsets := map[string]float64{}
		if watch.UptimeOffsetOf != "" {
			offsets = instantsByInstance(byName[watch.UptimeOffsetOf])
			if len(offsets) == 0 {
				// The marker is a system-uptime reading, so with no boot epoch to
				// add it is not an instant at all. Skipping is the only correct
				// answer: guessing the anchor would date the annotation wrongly.
				continue
			}
		}

		for _, metric := range family.GetMetric() {
			labels := labelMap(metric)
			value := metricValue(metric)
			if value <= 0 {
				continue
			}
			if watch.UptimeOffsetOf != "" {
				offset, ok := offsets[labels[instanceLabel]]
				if !ok {
					continue
				}
				value += offset
			}

			at := time.Unix(int64(value), 0)
			if at.Before(oldest) || at.After(newest) {
				continue
			}

			detail := detailValues(watch, labels)
			key := dedupeKey(watch.Kind, labels[instanceLabel], detail, at.UnixMilli())
			if _, ok := w.seen[key]; ok {
				continue
			}
			events = append(events, Event{
				Kind: watch.Kind,
				Text: eventText(watch, detail),
				At:   at,
				Tags: w.tags(watch, labels[instanceLabel], detail),
			})
		}
	}

	// Oldest first, so a cycle-cap truncation drops the newest events rather than
	// leaving a hole in the middle of the timeline.
	sort.Slice(events, func(i, j int) bool {
		if !events[i].At.Equal(events[j].At) {
			return events[i].At.Before(events[j].At)
		}
		return events[i].Kind < events[j].Kind
	})
	return events, nil
}

func (w *Watcher) markSeen(event Event) {
	kind, instance, detail := decodeTags(event.Tags)
	w.seen[dedupeKey(kind, instance, detail, event.At.UnixMilli())] = event.At.UnixMilli()
}

// prune drops dedupe entries that have aged out of the lookback window.
func (w *Watcher) prune(now time.Time) {
	cutoff := now.Add(-w.cfg.Lookback).UnixMilli()
	for key, at := range w.seen {
		if at < cutoff {
			delete(w.seen, key)
		}
	}
}

// tags builds the annotation's tag set. Every tag here is either a closed
// vocabulary (the event kind) or an identifier the metric itself carries under a
// label named in the catalogue — never an address, hostname or free-text field.
func (w *Watcher) tags(watch Watch, instance string, detail []string) []string {
	tags := []string{BaseTag, watch.Kind}
	if instance != "" {
		tags = append(tags, "instance:"+instance)
	}
	for i, key := range watch.LabelKeys {
		if i < len(detail) && detail[i] != "" {
			tags = append(tags, key+":"+detail[i])
		}
	}
	return append(tags, w.cfg.ExtraTags...)
}

// ---- helpers -------------------------------------------------------------

func labelMap(metric *dto.Metric) map[string]string {
	labels := make(map[string]string, len(metric.GetLabel()))
	for _, pair := range metric.GetLabel() {
		labels[pair.GetName()] = pair.GetValue()
	}
	return labels
}

func metricValue(metric *dto.Metric) float64 {
	if gauge := metric.GetGauge(); gauge != nil {
		return gauge.GetValue()
	}
	if untyped := metric.GetUntyped(); untyped != nil {
		return untyped.GetValue()
	}
	return 0
}

// instantsByInstance reduces a single-series-per-appliance family to a lookup. Used
// for the boot epoch that anchors uptime-relative markers.
func instantsByInstance(family *dto.MetricFamily) map[string]float64 {
	if family == nil {
		return nil
	}
	out := map[string]float64{}
	for _, metric := range family.GetMetric() {
		value := metricValue(metric)
		if value <= 0 {
			continue
		}
		out[labelMap(metric)[instanceLabel]] = value
	}
	return out
}

func detailValues(watch Watch, labels map[string]string) []string {
	detail := make([]string, 0, len(watch.LabelKeys))
	for _, key := range watch.LabelKeys {
		detail = append(detail, labels[key])
	}
	return detail
}

func eventText(watch Watch, detail []string) string {
	if len(detail) == 0 {
		return watch.Text
	}
	args := make([]any, len(detail))
	for i, value := range detail {
		args[i] = value
	}
	return fmt.Sprintf(watch.Text, args...)
}

func dedupeKey(kind, instance string, detail []string, atMillis int64) string {
	return strings.Join([]string{kind, instance, strings.Join(detail, "\x1f"),
		fmt.Sprint(atMillis)}, "|")
}

// decodeTags recovers (kind, instance, detail) from a tag list, so an annotation
// read back from Grafana keys the same way as one this process built. Detail values
// are returned sorted because tag order is not guaranteed to survive the round
// trip, and the key must not depend on it.
func decodeTags(tags []string) (kind, instance string, detail []string) {
	for _, tag := range tags {
		switch {
		case tag == BaseTag:
			continue
		case strings.HasPrefix(tag, "instance:"):
			instance = strings.TrimPrefix(tag, "instance:")
		case strings.Contains(tag, ":"):
			detail = append(detail, strings.SplitN(tag, ":", 2)[1])
		case kind == "":
			kind = tag
		}
	}
	sort.Strings(detail)
	return kind, instance, detail
}
