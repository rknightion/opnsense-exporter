package opnsense

import (
	"encoding/json"
	"github.com/rknightion/opnsense-exporter/internal/fetchshare"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

type ipsecSearchResponse struct {
	Rows []struct {
		Phase1desc  string `json:"phase1desc"`
		Connected   bool   `json:"connected"`
		IkeId       string `json:"ikeid"`
		Name        string `json:"name"`
		InstallTime string `json:"install-time"`
		// int64 so large byte/packet counters (>2^31) unmarshal correctly on
		// 32-bit source builds instead of failing the whole fetch (#103).
		BytesIn    int64 `json:"bytes-in"`
		BytesOut   int64 `json:"bytes-out"`
		PacketsIn  int64 `json:"packets-in"`
		PacketsOut int64 `json:"packets-out"`
	} `json:"rows"`
	RowCount int `json:"rowCount"`
	Total    int `json:"total"`
	Current  int `json:"current"`
}

type ipsecPhase2 struct {
	Phase2desc  string
	Name        string
	InstallTime int
	RekeyTime   int
	LifeTime    int
	// int64 so large byte/packet counters (>2^31) survive on 32-bit builds (#103).
	BytesIn    int64
	BytesOut   int64
	PacketsIn  int64
	PacketsOut int64
	// State is the vici child-SA state name (CREATED/ROUTED/INSTALLING/INSTALLED/
	// UPDATING/REKEYING/REKEYED/RETRYING/DELETING/DELETED/DESTROYING, per
	// strongSwan's child_sa_state_names) — #578. Phase1's Connected flag is an
	// IKE-SA-level aggregate and says nothing about any one child SA, so a
	// tunnel can read fully healthy while one child SA is dead; this is the
	// only field that exposes per-child-SA health.
	State string
}

type ipsecPhase2SearchResponse struct {
	Rows []struct {
		Phase2desc  string `json:"phase2desc"`
		Name        string `json:"name"`
		InstallTime string `json:"install-time"`
		RekeyTime   string `json:"rekey-time"`
		LifeTime    string `json:"life-time"`
		BytesIn     string `json:"bytes-in"`
		BytesOut    string `json:"bytes-out"`
		PacketsIn   string `json:"packets-in"`
		PacketsOut  string `json:"packets-out"`
		// State: see ipsecPhase2.State above (#578). Always a plain JSON string
		// in every capture seen so far (vici's add_kv "%N" enum formatter), unlike
		// several sibling fields on this same endpoint that need flex tolerance.
		State string `json:"state"`
	} `json:"rows"`
}

type IPsec struct {
	Phase1desc  string
	Connected   int
	IkeId       string
	Name        string
	InstallTime int
	// int64 so large byte/packet counters (>2^31) survive on 32-bit builds (#103).
	BytesIn    int64
	BytesOut   int64
	PacketsIn  int64
	PacketsOut int64
	Phase2     []ipsecPhase2
}

type IPsecPhase1 struct {
	Rows []IPsec
}

func (c *Client) FetchIPsecPhase2(ikeId string) (ipsecPhase2SearchResponse, *APICallError) {
	var resp ipsecPhase2SearchResponse

	url, ok := c.endpoints["ipsecPhase2"]

	if !ok {
		return resp, &APICallError{
			Endpoint:   "ipsecPhase2",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	body := map[string]string{"id": ikeId}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return resp, &APICallError{
			Endpoint:   "ipsecPhase2",
			Message:    "failed to marshal body",
			StatusCode: 0,
		}
	}

	if err := c.do("POST", url, strings.NewReader(string(bodyBytes)), &resp); err != nil {
		return resp, err
	}

	return resp, nil
}

func (c *Client) FetchIPsecPhase1() (IPsecPhase1, *APICallError) {
	var resp ipsecSearchResponse
	var data IPsecPhase1

	url, ok := c.endpoints["ipsecPhase1"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "ipsecPhase1",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return data, err
	}

	for _, v := range resp.Rows {

		installTime, err := strconv.Atoi(v.InstallTime)
		if err != nil {
			installTime = 0
		}

		phase2Rows := []ipsecPhase2{}
		phase2, err2 := c.FetchIPsecPhase2(v.IkeId)
		if err2 != nil {
			c.log.Error("failed to fetch ipsec phase2", "error", err2)
		} else {
			for _, v2 := range phase2.Rows {
				p2InstallTime, err := strconv.Atoi(v2.InstallTime)
				if err != nil {
					p2InstallTime = 0
				}
				rekeyTime, err := strconv.Atoi(v2.RekeyTime)
				if err != nil {
					rekeyTime = 0
				}
				lifeTime, err := strconv.Atoi(v2.LifeTime)
				if err != nil {
					lifeTime = 0
				}
				// safeAtoi (int64) so large byte/packet counters are preserved
				// rather than silently zeroed via int overflow on 32-bit (#103).
				bytesIn := safeAtoi(v2.BytesIn)
				bytesOut := safeAtoi(v2.BytesOut)
				packetsIn := safeAtoi(v2.PacketsIn)
				packetsOut := safeAtoi(v2.PacketsOut)
				phase2Rows = append(phase2Rows, ipsecPhase2{
					Phase2desc:  v2.Phase2desc,
					Name:        v2.Name,
					InstallTime: p2InstallTime,
					RekeyTime:   rekeyTime,
					LifeTime:    lifeTime,
					BytesIn:     bytesIn,
					BytesOut:    bytesOut,
					PacketsIn:   packetsIn,
					PacketsOut:  packetsOut,
					State:       v2.State,
				})
			}
		}
		data.Rows = append(data.Rows, IPsec{
			Phase1desc:  v.Phase1desc,
			IkeId:       v.IkeId,
			Name:        v.Name,
			InstallTime: installTime,
			BytesIn:     v.BytesIn,
			BytesOut:    v.BytesOut,
			PacketsIn:   v.PacketsIn,
			PacketsOut:  v.PacketsOut,
			Connected:   parseBoolToInt(v.Connected),
			Phase2:      phase2Rows,
		})
	}

	c.publishResult(fetchshare.KeyIPsecPhase1, data)
	return data, nil
}

// ipsecPoolRow mirrors one entry in the api/ipsec/leases/pools `pools` object
// map. Numbers are real JSON integers (Python ujson), not strings.
//
// VERIFICATION: endpoint is OPNsense core (LeasesController.php::poolsAction +
// scripts/ipsec/list_leases.py). Live-verification against the real box is
// encouraged; the populated fixture is derived from the controller source.
type ipsecPoolRow struct {
	Name    string  `json:"name"`
	Net     string  `json:"net"`
	Online  float64 `json:"online"`
	Offline float64 `json:"offline"`
	Size    float64 `json:"size"`
}

// IPsecPool is the normalised per-pool data.
type IPsecPool struct {
	Name    string
	Net     string
	Online  float64
	Offline float64
	Size    float64
}

// ipsecLeaseRow mirrors one entry in the `leases` array served alongside the
// pool rows by api/ipsec/leases/pools (LeasesController::poolsAction +
// scripts/ipsec/list_leases.py). It is the SAME per-lease data the separate
// api/ipsec/leases/search endpoint returns, so #213 feeds per-lease detail from
// this response rather than paying for a second identical swanctl exec.
// `address` is decoded for schema completeness only — it is never a metric label
// (per-client VIPs are unbounded, high-cardinality identity).
type ipsecLeaseRow struct {
	Pool    string   `json:"pool"`
	Address string   `json:"address"`
	Online  flexBool `json:"online"`
	User    string   `json:"user"`
}

// IPsecLease is one normalised mode-cfg lease.
type IPsecLease struct {
	Pool   string
	User   string
	Online bool
}

// IPsecPools holds all configured mode-cfg pools plus the per-lease detail,
// both returned by FetchIPsecPools from the single leases/pools response.
type IPsecPools struct {
	Pools  []IPsecPool  // sorted by Name
	Leases []IPsecLease // sorted by (Pool, User)
}

// ipsecPoolsResponse captures the top-level api/ipsec/leases/pools object.
// The `pools` field is a JSON array when unconfigured but an object map when
// pools exist — use json.RawMessage and try both. `leases` is a flat array of
// the active leases (empty/absent when none).
type ipsecPoolsResponse struct {
	Pools  json.RawMessage `json:"pools"`
	Leases []ipsecLeaseRow `json:"leases"`
}

// FetchIPsecPools fetches IPsec mode-cfg pool utilisation data plus per-lease
// detail (both live in the one leases/pools response — see ipsecLeaseRow).
//
// When no pools are configured, the API returns `{"pools": []}` (an array);
// when pools exist, `pools` is an object map keyed by pool name. A 404 is
// treated as "feature absent" — empty data, no error.
func (c *Client) FetchIPsecPools() (IPsecPools, *APICallError) {
	var data IPsecPools

	url, ok := c.endpoints["ipsecPools"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "ipsecPools",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	var resp ipsecPoolsResponse
	if err := c.do("GET", url, nil, &resp); err != nil {
		if err.StatusCode == http.StatusNotFound {
			return data, nil // defensive: feature absent
		}
		return data, err
	}

	// leases is present regardless of the pools array/object shape.
	for _, l := range resp.Leases {
		data.Leases = append(data.Leases, IPsecLease{
			Pool:   l.Pool,
			User:   l.User,
			Online: l.Online.Bool(),
		})
	}
	sort.Slice(data.Leases, func(i, j int) bool {
		if data.Leases[i].Pool != data.Leases[j].Pool {
			return data.Leases[i].Pool < data.Leases[j].Pool
		}
		return data.Leases[i].User < data.Leases[j].User
	})

	// pools is an array when unconfigured, an object map when populated.
	// Try to unmarshal as a map; on failure (e.g. empty array) leave pools empty
	// but keep any leases already parsed above.
	var poolMap map[string]ipsecPoolRow
	if err := json.Unmarshal(resp.Pools, &poolMap); err != nil || len(poolMap) == 0 {
		return data, nil
	}

	for _, row := range poolMap {
		data.Pools = append(data.Pools, IPsecPool(row))
	}
	sort.Slice(data.Pools, func(i, j int) bool {
		return data.Pools[i].Name < data.Pools[j].Name
	})

	return data, nil
}

// --- Kernel security-association database (setkey -D) --------------------------

// ipsecSadRow is one row of api/ipsec/sad/search. This is the live kernel SA
// table — never cached.
//
// Typing quirks (verified against a live established tunnel, #213/#195):
//   - reqid arrives as a bare JSON int here, but as a quoted string on
//     spd/search; flexInt tolerates both so the two endpoints can share nothing.
//   - spi is a hex string ("c6524517") and is the one numeric-looking field the
//     PHP parser does NOT int-cast. It MUST NOT become a label — it churns on
//     every rekey (the known SPI-cardinality backlog item).
//   - satype/spi are null on the synthetic "No SAD entries." placeholder row the
//     parser emits when setkey has nothing to report (it splits the plain-text
//     message into fake fields: src="No", dst="SAD", nat="ntries"). Those rows
//     are discarded in FetchIPsecSAD.
//   - nat is present ONLY under NAT-T; absent otherwise (not null/false).
//   - addtime_diff is the SA age in seconds; addtime_hard/soft are the hard/soft
//     rekey lifetimes in seconds.
//   - bytes_current/bytes_hard/bytes_soft and allocated/allocated_hard/
//     allocated_soft (#578) are the byte-count and packet-count ("allocations")
//     rekey mechanism siblings of addtime_*: byte/packet usage since the SA was
//     installed, and the hard/soft thresholds that trigger a rekey when hit.
//     Wire shape is inconsistent across releases the same way reqid/addtime are
//     (bare number on some, quoted string on others), hence flexString here too.
//     A hard/soft value of 0 is setkey/strongSwan's own convention for "no limit
//     configured" — NOT a real ceiling of zero — so the collector gates it out
//     of the emitted series rather than exporting a fabricated zero.
//   - usetime_hard/usetime_last/usetime_soft (idle-timeout rekey margins,
//     measured from last packet rather than from install) are deliberately NOT
//     decoded: idle-based lifetimes are a rarely-configured third clock next to
//     the already-modeled addtime (wall-clock) and the byte/allocated (volume)
//     ones, so they were dropped from scope rather than adding three more
//     near-always-zero series per child SA. Revisit if a real deployment turns
//     out to configure margintime.
type ipsecSadRow struct {
	Src           string     `json:"src"`
	Dst           string     `json:"dst"`
	SAType        string     `json:"satype"`
	SPI           string     `json:"spi"`
	ReqID         flexInt    `json:"reqid"`
	State         string     `json:"state"`
	AddtimeDiff   flexInt    `json:"addtime_diff"`
	AddtimeHard   flexInt    `json:"addtime_hard"`
	AddtimeSoft   flexInt    `json:"addtime_soft"`
	NAT           flexString `json:"nat"`
	IkeID         flexString `json:"ikeid"`
	Phase1desc    flexString `json:"phase1desc"`
	Phase2desc    flexString `json:"phase2desc"`
	BytesCurrent  flexString `json:"bytes_current"`
	BytesHard     flexString `json:"bytes_hard"`
	BytesSoft     flexString `json:"bytes_soft"`
	Allocated     flexString `json:"allocated"`
	AllocatedHard flexString `json:"allocated_hard"`
	AllocatedSoft flexString `json:"allocated_soft"`
}

type ipsecSadResponse struct {
	Rows []ipsecSadRow `json:"rows"`
}

// IPsecSA is one normalised live kernel SA entry.
type IPsecSA struct {
	SAType       string
	IkeID        string
	Phase1desc   string
	Phase2desc   string
	ReqID        string
	AgeSeconds   int
	LifetimeHard int
	LifetimeSoft int
	NATTraversal bool
	// Byte/packet usage + rekey limits (#578). int64 for the same reason
	// phase1/phase2 bytes-in/out are (#103): a busy or long-lived SA's cumulative
	// counters exceed 2^31 well within normal operation. A *Limit field of 0
	// means "unconfigured", not "already exhausted" — see ipsecSadRow's doc
	// comment; this struct makes no gating decision, it just carries the wire
	// value through.
	BytesCurrent       int64
	BytesHardLimit     int64
	BytesSoftLimit     int64
	AllocatedCurrent   int64
	AllocatedHardLimit int64
	AllocatedSoftLimit int64
}

// IPsecSAD holds the live kernel SA entries (placeholder rows discarded).
type IPsecSAD struct {
	Entries []IPsecSA
}

// FetchIPsecSAD fetches the kernel security-association database (setkey -D).
// Core endpoint — a body is never cached (live counters/state).
func (c *Client) FetchIPsecSAD() (IPsecSAD, *APICallError) {
	var data IPsecSAD

	url, ok := c.endpoints["ipsecSad"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "ipsecSad",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	var resp ipsecSadResponse
	if err := c.do("GET", url, nil, &resp); err != nil {
		return data, err
	}

	for _, r := range resp.Rows {
		// Discard the synthetic "No SAD entries." placeholder row: a real SA
		// always carries a satype (esp/ah) and a hex spi; the placeholder has
		// both null.
		if r.SPI == "" || r.SAType == "" {
			continue
		}
		data.Entries = append(data.Entries, IPsecSA{
			SAType:       r.SAType,
			IkeID:        r.IkeID.String(),
			Phase1desc:   r.Phase1desc.String(),
			Phase2desc:   r.Phase2desc.String(),
			ReqID:        strconv.Itoa(r.ReqID.Int()),
			AgeSeconds:   r.AddtimeDiff.Int(),
			LifetimeHard: r.AddtimeHard.Int(),
			LifetimeSoft: r.AddtimeSoft.Int(),
			NATTraversal: r.NAT.String() != "",
			// safeAtoi (int64), same reasoning as phase1/phase2 bytes-in/out (#103):
			// these are cumulative-since-install counters that can exceed 2^31.
			BytesCurrent:       safeAtoi(r.BytesCurrent.String()),
			BytesHardLimit:     safeAtoi(r.BytesHard.String()),
			BytesSoftLimit:     safeAtoi(r.BytesSoft.String()),
			AllocatedCurrent:   safeAtoi(r.Allocated.String()),
			AllocatedHardLimit: safeAtoi(r.AllocatedHard.String()),
			AllocatedSoftLimit: safeAtoi(r.AllocatedSoft.String()),
		})
	}

	return data, nil
}

// --- Kernel security-policy database (setkey -DP) ------------------------------

// ipsecSpdRow is one row of api/ipsec/spd/search. Live kernel policy table —
// never cached. Only the direction is consumed (policies are counted per
// direction); reqid/spid/seq/pid are strings here (unlike sad) and, like spi,
// would churn as labels, so they are ignored.
type ipsecSpdRow struct {
	Dir string `json:"dir"` // in / out / fwd
}

type ipsecSpdResponse struct {
	Rows []ipsecSpdRow `json:"rows"`
}

// IPsecSPD holds the direction of every installed kernel policy.
type IPsecSPD struct {
	Directions []string
}

// FetchIPsecSPD fetches the kernel security-policy database (setkey -DP).
// Core endpoint — a body is never cached (live table).
func (c *Client) FetchIPsecSPD() (IPsecSPD, *APICallError) {
	var data IPsecSPD

	url, ok := c.endpoints["ipsecSpd"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "ipsecSpd",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	var resp ipsecSpdResponse
	if err := c.do("GET", url, nil, &resp); err != nil {
		return data, err
	}

	for _, r := range resp.Rows {
		if r.Dir == "" {
			continue
		}
		data.Directions = append(data.Directions, r.Dir)
	}

	return data, nil
}

// --- Legacy subsystem status (pending-config flag) -----------------------------

// ipsecLegacyStatusResponse captures api/ipsec/legacy_subsystem/status —
// {enabled, isDirty}. Pure PHP (no exec): enabled reflects the ipsec master
// switch, isDirty flags an uncommitted (staged-but-not-applied) ipsec config
// change. Live flags — never cached.
type ipsecLegacyStatusResponse struct {
	Enabled flexBool `json:"enabled"`
	IsDirty flexBool `json:"isDirty"`
}

// IPsecLegacyStatus is the normalised legacy-subsystem status.
type IPsecLegacyStatus struct {
	Enabled bool
	IsDirty bool
}

// FetchIPsecLegacyStatus fetches the ipsec enabled/dirty flags.
func (c *Client) FetchIPsecLegacyStatus() (IPsecLegacyStatus, *APICallError) {
	var data IPsecLegacyStatus

	url, ok := c.endpoints["ipsecLegacyStatus"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "ipsecLegacyStatus",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	var resp ipsecLegacyStatusResponse
	if err := c.do("GET", url, nil, &resp); err != nil {
		return data, err
	}

	data.Enabled = resp.Enabled.Bool()
	data.IsDirty = resp.IsDirty.Bool()
	return data, nil
}
