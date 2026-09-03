package logship

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rknightion/opnsense2otel/v4/internal/options"
	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

const (
	// routingChangeSourceName is the stable pipeline source identity. It must be
	// distinct from configstate because source names key state-file entries and
	// self-metric labels.
	routingChangeSourceName = "routingchange"
	routingChangeSubsystem  = "routing"
	routingChangeSchema     = "opnsense.routing.change.v1"
	routingChangeEvent      = "default_route_change"

	// routingChangeMinInterval is both the source poll floor and the event
	// cooldown. A route failover is useful evidence, but repeatedly exporting the
	// same box while a gateway oscillates is not. Keeping the two bounds aligned
	// also makes the maximum event rate obvious: one event per minute per source.
	routingChangeMinInterval = time.Minute

	routingChangeStateSchema = 1

	// routingChangeMaxSuppressed bounds the persisted counter during an outage
	// that never settles. The source already holds a constant-size pending state;
	// this additionally prevents the count itself from wrapping after a very long
	// flap.
	routingChangeMaxSuppressed = uint64(^uint32(0))
)

// RoutingChangeSourceName is the value used by Source.Name and by the pipeline's
// opnsense.source resource attribute for this lane.
const RoutingChangeSourceName = routingChangeSourceName

// RoutingChangeSubsystem is the closed opnsense.subsystem value carried by
// routing-change records.
const RoutingChangeSubsystem = routingChangeSubsystem

// RoutingChangeSchema is the versioned body schema for default-route events.
const RoutingChangeSchema = routingChangeSchema

// RoutingChangeMinInterval is the poll and event-rate floor for this source.
const RoutingChangeMinInterval = routingChangeMinInterval

// RoutingSnapshot is the current, already-decoded view of the two OPNsense
// endpoints used by this source. DefaultRoutes comes from routingTable's
// default destinations; Gateways comes from gatewaysStatus. The source projects
// these structs to a stable JSON shape before diffing and shipping.
//
// The public seam makes source tests independent of HTTP fixtures while keeping
// the production adapter below responsible for the OPNsense client methods.
type RoutingSnapshot struct {
	DefaultRoutes []opnsense.DefaultRoute
	Gateways      []opnsense.Gateway
}

// RoutingChangeFetcher is the narrow API seam needed by the routing source.
// Implementations must return one coherent pair of endpoint snapshots for a
// poll. A failed fetch must return an error; the source will retain its prior
// cursor and retry the whole pair at the next tick.
type RoutingChangeFetcher interface {
	FetchRoutingSnapshot(context.Context) (RoutingSnapshot, error)
}

type opnsenseRoutingChangeFetcher struct{ client *opnsense.Client }

func (f opnsenseRoutingChangeFetcher) FetchRoutingSnapshot(ctx context.Context) (RoutingSnapshot, error) {
	client := f.client.WithContext(ctx)
	routes, apiErr := client.FetchRouteStatistics()
	if apiErr != nil {
		return RoutingSnapshot{}, apiErr
	}
	gateways, apiErr := client.FetchGateways()
	if apiErr != nil {
		return RoutingSnapshot{}, apiErr
	}
	return RoutingSnapshot{
		DefaultRoutes: routes.DefaultRoutes,
		Gateways:      gateways.Gateways,
	}, nil
}

func init() {
	RegisterSource(func(deps Deps) (Source, error) {
		if !options.LogsConfigSnapshotRoutingChangesEnabled() {
			return nil, nil
		}
		return NewRoutingChangeSource(opnsenseRoutingChangeFetcher{client: deps.Client}, deps.Logger), nil
	})
}

// routeChangeState is the JSON-safe projection retained in memory and persisted
// in --logs.state-file. It intentionally carries the gateway status in addition
// to the route identity so a before/after record explains a failover, while the
// diff fingerprint below excludes volatile dpinger readings.
type routeChangeState struct {
	RoutingTable   routeTableState     `json:"routingTable"`
	GatewaysStatus gatewaysStatusState `json:"gatewaysStatus"`
}

type routeTableState struct {
	DefaultRoutes []routeState `json:"default_routes"`
}

type routeState struct {
	Proto     string `json:"proto"`
	Device    string `json:"device"`
	Interface string `json:"interface"`
	Gateway   string `json:"gateway"`
}

type gatewaysStatusState struct {
	Rows []gatewayState `json:"rows"`
}

type gatewayState struct {
	UUID                 string `json:"uuid,omitempty"`
	Name                 string `json:"name,omitempty"`
	Description          string `json:"description,omitempty"`
	HardwareInterface    string `json:"hardware_interface,omitempty"`
	IPProtocol           string `json:"ip_protocol,omitempty"`
	Gateway              string `json:"gateway,omitempty"`
	DefaultGateway       bool   `json:"default_gateway"`
	Enabled              bool   `json:"enabled"`
	FarGateway           string `json:"far_gateway,omitempty"`
	Interface            string `json:"interface,omitempty"`
	InterfaceDescription string `json:"interface_description,omitempty"`
	Upstream             bool   `json:"upstream"`
	Status               string `json:"status,omitempty"`
}

// routingChangeFingerprint is deliberately narrower than routeChangeState:
// gateway status, probe results and display text are context, not a route move.
// Stable gateway configuration is included because a default-gateway selection
// can change before the kernel table reflects it, and because the two endpoint
// snapshots are one logical signal.
type routingChangeFingerprint struct {
	DefaultRoutes []routeState        `json:"default_routes"`
	Gateways      []gatewayRouteState `json:"gateways"`
}

type gatewayRouteState struct {
	UUID              string `json:"uuid,omitempty"`
	Name              string `json:"name,omitempty"`
	HardwareInterface string `json:"hardware_interface,omitempty"`
	IPProtocol        string `json:"ip_protocol,omitempty"`
	Gateway           string `json:"gateway,omitempty"`
	DefaultGateway    bool   `json:"default_gateway"`
	Enabled           bool   `json:"enabled"`
	FarGateway        string `json:"far_gateway,omitempty"`
	Interface         string `json:"interface,omitempty"`
	Upstream          bool   `json:"upstream"`
}

type routingChangeEventBody struct {
	Schema string           `json:"schema"`
	Event  string           `json:"event"`
	Family string           `json:"family"`
	Before routeChangeState `json:"before"`
	After  routeChangeState `json:"after"`
	Flap   *routingFlap     `json:"flap,omitempty"`
}

type routingFlap struct {
	Kind              string `json:"kind"`
	SuppressedChanges uint64 `json:"suppressed_changes"`
}

type routingChangePending struct {
	Before            routeChangeState `json:"before"`
	SuppressedChanges uint64           `json:"suppressed_changes"`
}

type routingChangePersistedState struct {
	Schema          int                   `json:"schema"`
	CursorSet       bool                  `json:"cursor_set"`
	LastSnapshot    routeChangeState      `json:"last_snapshot"`
	LastEmittedAt   time.Time             `json:"last_emitted_at"`
	LastEmissionSet bool                  `json:"last_emission_set"`
	Pending         *routingChangePending `json:"pending,omitempty"`
}

// RoutingChangeSource emits one before/after event when the effective default
// route or default-gateway configuration changes. The first successful poll is
// a baseline and emits nothing. During the cooldown, changes are coalesced into
// one flap detail event instead of one record per poll.
type RoutingChangeSource struct {
	fetcher RoutingChangeFetcher
	log     *slog.Logger
	now     func() time.Time

	mu              sync.Mutex
	cursorSet       bool
	lastSnapshot    routeChangeState
	lastEmittedAt   time.Time
	lastEmissionSet bool
	pending         *routingChangePending
	interval        time.Duration
}

// NewRoutingChangeSource builds the source with production time and cooldown
// behaviour. The source uses the existing logship pipeline for polling,
// backpressure, delivery and state-file persistence; it does not start a second
// goroutine or sink.
func NewRoutingChangeSource(fetcher RoutingChangeFetcher, log *slog.Logger) *RoutingChangeSource {
	return newRoutingChangeSource(fetcher, log, time.Now, routingChangeMinInterval)
}

func newRoutingChangeSource(fetcher RoutingChangeFetcher, log *slog.Logger, now func() time.Time, interval time.Duration) *RoutingChangeSource {
	if log == nil {
		log = slog.Default()
	}
	if now == nil {
		now = time.Now
	}
	if interval <= 0 {
		interval = routingChangeMinInterval
	}
	return &RoutingChangeSource{
		fetcher: fetcher,
		log:     log,
		now:     now,
		// interval is kept in the source rather than read from a process-global
		// mutable setting, so independent source instances cannot race.
		interval: interval,
	}
}

// Name implements Source.
func (s *RoutingChangeSource) Name() string { return routingChangeSourceName }

// MinInterval implements IntervalSource. The poll floor is intentionally the
// same as the event cooldown: this source cannot produce more than one event per
// minute even if the global log poll interval is shorter.
func (s *RoutingChangeSource) MinInterval() time.Duration { return s.interval }

// Poll fetches one coherent pair of route/gateway snapshots and compares it with
// the last successful snapshot. A fetch error leaves the cursor untouched so a
// transiently unavailable endpoint cannot manufacture a route loss or advance
// past a real movement.
func (s *RoutingChangeSource) Poll(ctx context.Context) ([]Record, error) {
	snapshot, err := s.fetcher.FetchRoutingSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	current := projectRoutingSnapshot(snapshot)
	now := s.now().UTC()

	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.cursorSet {
		s.lastSnapshot = current
		s.cursorSet = true
		return nil, nil
	}

	previous := s.lastSnapshot
	changed := routingStateChanged(previous, current)
	if changed {
		if s.eventAllowed(now) {
			before := previous
			var suppressed uint64
			if s.pending != nil {
				before = s.pending.Before
				suppressed = s.pending.SuppressedChanges
			}
			record, err := routingChangeRecord(before, current, now, suppressed)
			if err != nil {
				return nil, err
			}
			s.lastSnapshot = current
			s.pending = nil
			s.lastEmittedAt = now
			s.lastEmissionSet = true
			return []Record{record}, nil
		}

		if s.pending == nil {
			s.pending = &routingChangePending{Before: previous}
		}
		if s.pending.SuppressedChanges < routingChangeMaxSuppressed {
			s.pending.SuppressedChanges++
		}
		s.lastSnapshot = current
		return nil, nil
	}

	// A quiet poll after the cooldown flushes a coalesced flap. This preserves
	// the fact that a route moved and returned even when no new movement happens
	// after the cooldown expires.
	if s.pending != nil && s.eventAllowed(now) {
		record, err := routingChangeRecord(s.pending.Before, current, now, s.pending.SuppressedChanges)
		if err != nil {
			return nil, err
		}
		s.pending = nil
		s.lastEmittedAt = now
		s.lastEmissionSet = true
		s.lastSnapshot = current
		return []Record{record}, nil
	}

	s.lastSnapshot = current
	return nil, nil
}

func (s *RoutingChangeSource) eventAllowed(now time.Time) bool {
	return !s.lastEmissionSet || now.Sub(s.lastEmittedAt) >= s.interval
}

// LoadState implements StatefulSource. A malformed or foreign-version blob is
// ignored, which means the next successful poll becomes a fresh baseline rather
// than replaying an arbitrarily old route movement.
func (s *RoutingChangeSource) LoadState(data []byte) {
	var state routingChangePersistedState
	if len(data) == 0 || json.Unmarshal(data, &state) != nil ||
		state.Schema != routingChangeStateSchema || !state.CursorSet {
		return
	}
	if state.Pending != nil && state.Pending.SuppressedChanges > routingChangeMaxSuppressed {
		state.Pending.SuppressedChanges = routingChangeMaxSuppressed
	}
	s.mu.Lock()
	s.cursorSet = true
	s.lastSnapshot = state.LastSnapshot
	s.lastEmittedAt = state.LastEmittedAt
	s.lastEmissionSet = state.LastEmissionSet
	s.pending = state.Pending
	s.mu.Unlock()
}

// SaveState implements StatefulSource. State includes the baseline even when no
// route has moved yet, so a restart does not turn an unchanged box into a first
// artificial event.
func (s *RoutingChangeSource) SaveState() ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.cursorSet {
		return nil, false
	}
	state := routingChangePersistedState{
		Schema:          routingChangeStateSchema,
		CursorSet:       true,
		LastSnapshot:    s.lastSnapshot,
		LastEmittedAt:   s.lastEmittedAt,
		LastEmissionSet: s.lastEmissionSet,
		Pending:         s.pending,
	}
	data, err := json.Marshal(state)
	if err != nil {
		return nil, false
	}
	return data, true
}

func projectRoutingSnapshot(snapshot RoutingSnapshot) routeChangeState {
	routes := make([]routeState, 0, len(snapshot.DefaultRoutes))
	for _, route := range snapshot.DefaultRoutes {
		routes = append(routes, routeState{
			Proto:     route.Proto,
			Device:    route.Device,
			Interface: route.Interface,
			Gateway:   route.Gateway,
		})
	}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Proto != routes[j].Proto {
			return routes[i].Proto < routes[j].Proto
		}
		if routes[i].Gateway != routes[j].Gateway {
			return routes[i].Gateway < routes[j].Gateway
		}
		if routes[i].Device != routes[j].Device {
			return routes[i].Device < routes[j].Device
		}
		return routes[i].Interface < routes[j].Interface
	})

	gateways := make([]gatewayState, 0, len(snapshot.Gateways))
	for _, gateway := range snapshot.Gateways {
		gateways = append(gateways, gatewayState{
			UUID:                 gateway.UUID,
			Name:                 gateway.Name,
			Description:          gateway.Description,
			HardwareInterface:    gateway.HardwareInterface,
			IPProtocol:           gateway.IPProtocol,
			Gateway:              gateway.Gateway,
			DefaultGateway:       gateway.DefaultGateway,
			Enabled:              gateway.Enabled,
			FarGateway:           gateway.FarGateway,
			Interface:            gateway.Interface,
			InterfaceDescription: gateway.InterfaceDescription,
			Upstream:             gateway.Upstream,
			Status:               routingGatewayStatus(gateway.Status),
		})
	}
	sort.Slice(gateways, func(i, j int) bool {
		if gateways[i].UUID != gateways[j].UUID {
			return gateways[i].UUID < gateways[j].UUID
		}
		if gateways[i].Name != gateways[j].Name {
			return gateways[i].Name < gateways[j].Name
		}
		if gateways[i].IPProtocol != gateways[j].IPProtocol {
			return gateways[i].IPProtocol < gateways[j].IPProtocol
		}
		return gateways[i].Gateway < gateways[j].Gateway
	})

	return routeChangeState{
		RoutingTable:   routeTableState{DefaultRoutes: routes},
		GatewaysStatus: gatewaysStatusState{Rows: gateways},
	}
}

func routingGatewayStatus(status opnsense.GatewayStatusType) string {
	switch status {
	case opnsense.GatewayStatusOnline:
		return "online"
	case opnsense.GatewayStatusOffline:
		return "offline"
	case opnsense.GatewayStatusPeding:
		return "pending"
	case opnsense.GatewayStatusLoss:
		return "packetloss"
	case opnsense.GatewayStatusLatency:
		return "latency"
	case opnsense.GatewayStatusForcedDown:
		return "forced_down"
	default:
		return "unknown"
	}
}

func routingStateChanged(before, after routeChangeState) bool {
	return !reflect.DeepEqual(routingChangeFingerprintFor(before), routingChangeFingerprintFor(after))
}

func routingChangeFingerprintFor(state routeChangeState) routingChangeFingerprint {
	gateways := make([]gatewayRouteState, 0, len(state.GatewaysStatus.Rows))
	for _, gateway := range state.GatewaysStatus.Rows {
		gateways = append(gateways, gatewayRouteState{
			UUID:              gateway.UUID,
			Name:              gateway.Name,
			HardwareInterface: gateway.HardwareInterface,
			IPProtocol:        gateway.IPProtocol,
			Gateway:           gateway.Gateway,
			DefaultGateway:    gateway.DefaultGateway,
			Enabled:           gateway.Enabled,
			FarGateway:        gateway.FarGateway,
			Interface:         gateway.Interface,
			Upstream:          gateway.Upstream,
		})
	}
	return routingChangeFingerprint{
		DefaultRoutes: state.RoutingTable.DefaultRoutes,
		Gateways:      gateways,
	}
}

func routingChangeRecord(before, after routeChangeState, now time.Time, suppressed uint64) (Record, error) {
	event := routingChangeEventBody{
		Schema: routingChangeSchema,
		Event:  routingChangeEvent,
		Family: "default_route",
		Before: before,
		After:  after,
	}
	if suppressed > 0 {
		event.Flap = &routingFlap{
			Kind:              "coalesced",
			SuppressedChanges: suppressed,
		}
	}
	body, err := marshalRoutingChangeEvent(event)
	if err != nil {
		return Record{}, err
	}
	attrs := map[string]string{
		AttrSubsystem:  routingChangeSubsystem,
		"event":        routingChangeEvent,
		"change":       "default_route",
		"route_family": routeFamilies(after),
	}
	if suppressed > 0 {
		attrs["change_kind"] = "flap"
		attrs["flap_suppressed"] = strconv.FormatUint(suppressed, 10)
	} else {
		attrs["change_kind"] = "move"
	}
	return Record{Timestamp: now, Body: body, Attributes: attrs}, nil
}

func routeFamilies(state routeChangeState) string {
	families := make(map[string]struct{})
	for _, route := range state.RoutingTable.DefaultRoutes {
		if route.Proto != "" {
			families[route.Proto] = struct{}{}
		}
	}
	if len(families) == 0 {
		for _, gateway := range state.GatewaysStatus.Rows {
			if gateway.DefaultGateway && gateway.IPProtocol != "" {
				families[gateway.IPProtocol] = struct{}{}
			}
		}
	}
	ordered := make([]string, 0, len(families))
	for family := range families {
		ordered = append(ordered, family)
	}
	sort.Strings(ordered)
	return strings.Join(ordered, ",")
}

func marshalRoutingChangeEvent(event routingChangeEventBody) (string, error) {
	data, err := json.Marshal(event)
	if err != nil {
		return "", fmt.Errorf("marshal routing-change event: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return "", fmt.Errorf("decode routing-change event for redaction: %w", err)
	}
	redactRoutingChangeValue(value)
	data, err = json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("marshal redacted routing-change event: %w", err)
	}
	return string(data), nil
}

// redactRoutingChangeValue recursively removes configuration keys that name
// credentials. The matcher is deliberately shared with config snapshots and
// config revision diffs; this source must not grow a third sensitive-key list.
func redactRoutingChangeValue(value any) {
	switch value := value.(type) {
	case map[string]any:
		for key, child := range value {
			if opnsense.SensitiveConfigKey(key) {
				delete(value, key)
				continue
			}
			redactRoutingChangeValue(child)
		}
	case []any:
		for _, child := range value {
			redactRoutingChangeValue(child)
		}
	}
}

var _ Source = (*RoutingChangeSource)(nil)
var _ StatefulSource = (*RoutingChangeSource)(nil)
var _ IntervalSource = (*RoutingChangeSource)(nil)
