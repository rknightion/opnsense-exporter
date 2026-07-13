package opnsense

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

// monitStatusEnvelope is the top-level JSON wrapper for api/monit/status/get/xml.
//
// The OPNsense Monit controller (Monit/Api/StatusController.php) proxies the
// monit httpd and returns the XML status doc parsed by simplexml_load_string and
// JSON-encoded by the Phalcon framework. There are two distinct shapes:
//
//   - When monit is running: {"result":"ok","status":{...XML object...}}
//   - When monit is stopped: {"result":"failed","status":"<error message string>"}
//
// Status is therefore decoded as json.RawMessage and inspected at runtime.
//
// VERIFICATION: Both shapes are live-validated against real OPNsense boxes.
// The "failed" shape was validated against a 26.1 box with monit
// installed-but-not-running (2026-06-09). The "ok" shape, including the
// per-check resource fields (filesystem block/inode, process cpu/memory,
// host icmp/port response times, system load/memory/swap), was validated
// against a 26.7-devel box with one check of each of those types configured
// and monit actively running (2026-07-13).
type monitStatusEnvelope struct {
	Result string          `json:"result"`
	Status json.RawMessage `json:"status"`
}

// monitStatusBody is the inner object when result=="ok".
// It contains the list of monitored services under the "service" key.
// A single service is serialised as an object; multiple services as an array
// (standard SimpleXML→JSON quirk for repeated child elements).
type monitStatusBody struct {
	Service json.RawMessage `json:"service"`
}

// monitBlockXML is the filesystem block (space) usage node of a type=0
// (filesystem) check: monit's block.percent/usage/total. Only percent is
// modelled today; usage/total are available in the payload if a byte-level
// metric is wanted later.
type monitBlockXML struct {
	Percent flexString `json:"percent"`
}

// monitInodeXML is the filesystem inode usage node of a type=0 (filesystem) check.
type monitInodeXML struct {
	Percent flexString `json:"percent"`
}

// monitPercentKilobyteXML is the shared percent+kilobyte shape used by both a
// process check's memory node and a system check's memory node.
type monitPercentKilobyteXML struct {
	Percent  flexString `json:"percent"`
	Kilobyte flexString `json:"kilobyte"`
}

// monitCPUXML is a type=3 (process) check's cpu node: a scalar percent (plus
// percenttotal, unused today). Monit encodes "not yet computed" (before the
// second poll cycle completes) as -1; callers must treat a negative value as
// absent, not a real reading.
type monitCPUXML struct {
	Percent flexString `json:"percent"`
}

// monitICMPXML is a type=4 (host) check's icmp node.
type monitICMPXML struct {
	ResponseTime flexString `json:"responsetime"`
}

// monitPortXML is a single port/connection test under a type=4 (host) check.
// Like the top-level service list, repeated "port" children serialise as an
// array but a single one serialises as a bare object.
type monitPortXML struct {
	PortNumber   flexString `json:"portnumber"`
	Protocol     flexString `json:"protocol"`
	ResponseTime flexString `json:"responsetime"`
}

// monitLoadXML is a type=5 (system) check's load-average node.
type monitLoadXML struct {
	Avg01 flexString `json:"avg01"`
	Avg05 flexString `json:"avg05"`
	Avg15 flexString `json:"avg15"`
}

// monitSwapXML is a type=5 (system) check's swap node.
type monitSwapXML struct {
	Percent flexString `json:"percent"`
}

// monitSystemXML is a type=5 (system) check's "system" node. CPU is decoded
// as a map because the set of reported modes is platform-dependent: OPNsense
// (FreeBSD) reports user/system/nice/hardirq (verified 2026-07-13); other
// monit platforms are documented to report user/system/wait instead. Decoding
// as a map captures whatever modes are actually present without hardcoding
// either platform's field set.
type monitSystemXML struct {
	Load   monitLoadXML            `json:"load"`
	CPU    map[string]flexString   `json:"cpu"`
	Memory monitPercentKilobyteXML `json:"memory"`
	Swap   monitSwapXML            `json:"swap"`
}

// monitServiceXML is a single service entry from the monit XML status.
// Most scalar fields are XML text nodes, so they arrive as JSON strings —
// decoded via flexString so empty/missing fields parse cleanly. Per-type
// resource nodes (block/inode, memory/cpu, icmp/port, system) are only
// present in the payload for their matching @attributes.type; for any other
// type the corresponding Go field simply decodes to its zero value and is
// never read (callers gate access on Attributes.Type via monitTypeName).
type monitServiceXML struct {
	Attributes struct {
		Type flexString `json:"type"`
	} `json:"@attributes"`
	Name          flexString `json:"name"`
	Status        flexString `json:"status"`
	Monitor       flexString `json:"monitor"`
	PendingAction flexString `json:"pendingaction"`

	// type=0 (filesystem).
	Block monitBlockXML `json:"block"`
	Inode monitInodeXML `json:"inode"`

	// type=3 (process). Uptime and Threads are top-level XML fields that a
	// type=5 (system) check also emits (host/machine uptime has no "threads"
	// sibling, but shares the "uptime" key) — only meaningful when Type is
	// "process".
	Uptime  flexString              `json:"uptime"`
	Threads flexString              `json:"threads"`
	Memory  monitPercentKilobyteXML `json:"memory"`
	CPU     monitCPUXML             `json:"cpu"`

	// type=4 (host).
	ICMP monitICMPXML    `json:"icmp"`
	Port json.RawMessage `json:"port"`

	// type=5 (system).
	System monitSystemXML `json:"system"`
}

// MonitPortCheck is a single port/connection test result under a monit host
// (type=4) check.
type MonitPortCheck struct {
	// Port is the numeric port tested, as a string (e.g. "22").
	Port string
	// Protocol is the application protocol tested (e.g. "SSH", "HTTP").
	Protocol string
	// ResponseSeconds is the connection response time in seconds.
	ResponseSeconds float64
}

// MonitCheck is the normalised representation of a single monit service check.
//
// Resource fields are nil (or an empty slice for Ports) when the underlying
// monit payload did not carry that value for this check — either because the
// check's type does not produce it, or because monit itself has not computed
// it yet (e.g. process CPU percent reads -1 until the second poll cycle).
// Absent data is never coerced to zero: the collector must skip emitting a
// series when a pointer is nil.
type MonitCheck struct {
	// Name is the monit service name.
	Name string
	// Type is a stable string label derived from the monit numeric service type.
	Type string
	// StatusOK is 1 when the monit status field equals "0" (no error), 0 otherwise.
	StatusOK float64
	// Monitored is 1 when the monitor field is non-zero (actively monitored).
	Monitored float64

	// Filesystem (Type == "filesystem") resource fields.
	FilesystemUsagePercent      *float64
	FilesystemInodeUsagePercent *float64

	// Process (Type == "process") resource fields.
	ProcessCPUPercent    *float64
	ProcessMemoryBytes   *float64
	ProcessUptimeSeconds *float64
	ProcessThreads       *float64

	// Host (Type == "host") resource fields.
	ICMPResponseSeconds *float64
	Ports               []MonitPortCheck

	// System (Type == "system") resource fields.
	SystemLoad1         *float64
	SystemLoad5         *float64
	SystemLoad15        *float64
	SystemMemoryPercent *float64
	SystemSwapPercent   *float64
	// SystemCPU maps a platform-reported CPU mode (e.g. "user", "system",
	// "nice", "hardirq", "wait") to its percent value. Only modes actually
	// present in the payload are included.
	SystemCPU map[string]float64
}

// MonitStatus is the normalised result of FetchMonitStatus.
type MonitStatus struct {
	// StatusOK is true when result=="ok" and the status field decoded as an object.
	// It is false when monit is stopped or its httpd is unreachable.
	StatusOK bool
	// Checks holds per-service check data; empty when StatusOK is false.
	Checks []MonitCheck
}

// monitTypeName maps monit's numeric service type (from @attributes.type) to a
// stable, human-readable label value. The type integers are defined in monit's
// source (monit.h: TYPE_FILESYSTEM=0, TYPE_DIRECTORY=1, TYPE_FILE=2,
// TYPE_PROCESS=3, TYPE_HOST=4, TYPE_SYSTEM=5, TYPE_FIFO=6, TYPE_PROGRAM=7,
// TYPE_NET=8).
func monitTypeName(t string) string {
	switch t {
	case "0":
		return "filesystem"
	case "1":
		return "directory"
	case "2":
		return "file"
	case "3":
		return "process"
	case "4":
		return "host"
	case "5":
		return "system"
	case "6":
		return "fifo"
	case "7":
		return "program"
	case "8":
		return "network"
	default:
		return "unknown"
	}
}

// decodeXMLNodes decodes a SimpleXML-serialised repeated-child field that PHP's
// json_encode represents as a JSON array when there are 2+ elements but as a
// bare object when there is exactly one, and omits the key entirely when there
// are none. It returns nil for absent/empty input or an unrecognised shape.
func decodeXMLNodes[T any](raw json.RawMessage) []T {
	if len(raw) == 0 {
		return nil
	}

	var list []T
	if err := json.Unmarshal(raw, &list); err == nil {
		return list
	}

	var single T
	if err := json.Unmarshal(raw, &single); err != nil {
		return nil
	}
	return []T{single}
}

// flexFloatPtr parses a flexString to a *float64, returning nil when the value
// is empty or unparseable rather than coercing it to zero — absent monit data
// must produce an absent series, never a fabricated zero reading.
func flexFloatPtr(f flexString) *float64 {
	s := strings.TrimSpace(f.String())
	if s == "" {
		return nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return nil
	}
	return &v
}

// flexFloatPtrNonNegative is flexFloatPtr but additionally treats a negative
// value as absent. Monit encodes "not yet computed" (before its second poll
// cycle completes) as -1 on some per-check resource fields, e.g. process
// cpu.percent — verified against a live dev-box capture (2026-07-13).
func flexFloatPtrNonNegative(f flexString) *float64 {
	v := flexFloatPtr(f)
	if v != nil && *v < 0 {
		return nil
	}
	return v
}

// FetchMonitStatus calls api/monit/status/get/xml and returns the parsed monit
// service-check status.
//
// The endpoint never returns HTTP 404 on a standard OPNsense install (monit is
// a core package), but a 404 is treated as "feature absent" (empty data, nil
// error) to handle stripped builds gracefully. When monit is installed but not
// running, the API returns a JSON error envelope with result=="failed" and a
// plain-text string in the status field; FetchMonitStatus returns
// MonitStatus{StatusOK:false} in that case.
func (c *Client) FetchMonitStatus() (MonitStatus, *APICallError) {
	var data MonitStatus

	url, ok := c.endpoints["monitStatus"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "monitStatus",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	var envelope monitStatusEnvelope
	if err := c.do("GET", url, nil, &envelope); err != nil {
		if err.StatusCode == http.StatusNotFound {
			return data, nil // feature absent: silent
		}
		return data, err
	}

	// result != "ok" means monit is stopped or its httpd is unreachable.
	// The status field contains a plain-text error string in this case.
	if envelope.Result != "ok" {
		return data, nil // StatusOK stays false
	}

	// Decode the inner status object to reach the service list.
	var body monitStatusBody
	if err := json.Unmarshal(envelope.Status, &body); err != nil {
		// If status decodes as something other than an object (e.g. a string
		// on older controller versions) treat as no-data gracefully.
		return data, nil
	}

	data.StatusOK = true

	if len(body.Service) == 0 {
		return data, nil
	}

	services := decodeXMLNodes[monitServiceXML](body.Service)
	for _, svc := range services {
		statusOK := 0.0
		if svc.Status.String() == "0" {
			statusOK = 1.0
		}
		monitored := 0.0
		if svc.Monitor.String() != "0" {
			monitored = 1.0
		}

		checkType := monitTypeName(svc.Attributes.Type.String())
		check := MonitCheck{
			Name:      svc.Name.String(),
			Type:      checkType,
			StatusOK:  statusOK,
			Monitored: monitored,
		}

		switch checkType {
		case "filesystem":
			check.FilesystemUsagePercent = flexFloatPtr(svc.Block.Percent)
			check.FilesystemInodeUsagePercent = flexFloatPtr(svc.Inode.Percent)

		case "process":
			check.ProcessCPUPercent = flexFloatPtrNonNegative(svc.CPU.Percent)
			if kb := flexFloatPtr(svc.Memory.Kilobyte); kb != nil {
				bytes := *kb * 1024
				check.ProcessMemoryBytes = &bytes
			}
			check.ProcessUptimeSeconds = flexFloatPtr(svc.Uptime)
			check.ProcessThreads = flexFloatPtr(svc.Threads)

		case "host":
			check.ICMPResponseSeconds = flexFloatPtr(svc.ICMP.ResponseTime)
			for _, p := range decodeXMLNodes[monitPortXML](svc.Port) {
				rt := flexFloatPtr(p.ResponseTime)
				if rt == nil {
					continue
				}
				check.Ports = append(check.Ports, MonitPortCheck{
					Port:            p.PortNumber.String(),
					Protocol:        p.Protocol.String(),
					ResponseSeconds: *rt,
				})
			}

		case "system":
			check.SystemLoad1 = flexFloatPtr(svc.System.Load.Avg01)
			check.SystemLoad5 = flexFloatPtr(svc.System.Load.Avg05)
			check.SystemLoad15 = flexFloatPtr(svc.System.Load.Avg15)
			check.SystemMemoryPercent = flexFloatPtr(svc.System.Memory.Percent)
			check.SystemSwapPercent = flexFloatPtr(svc.System.Swap.Percent)
			if len(svc.System.CPU) > 0 {
				modes := make(map[string]float64, len(svc.System.CPU))
				for mode, raw := range svc.System.CPU {
					if v := flexFloatPtr(raw); v != nil {
						modes[mode] = *v
					}
				}
				if len(modes) > 0 {
					check.SystemCPU = modes
				}
			}
		}

		data.Checks = append(data.Checks, check)
	}

	return data, nil
}
