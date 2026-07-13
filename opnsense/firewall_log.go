package opnsense

import (
	"net/url"
	"strconv"
)

// FirewallLogRecord is one parsed filterlog event returned by
// api/diagnostics/firewall/log (configd `filter read log` → read_log.py). Every
// field arrives as a string — read_log.py emits the pf CSV columns verbatim
// without retyping — so every field is modelled as a string here and any
// numeric interpretation is left to the consumer.
//
// The three fields that make this endpoint worth polling over native filterlog
// syslog are __digest__ (the md5 cursor that makes lossless tailing possible),
// __timestamp__ (the event time read_log.py stamps), and Label — the human rule
// description the backend resolves from Rid against /tmp/rules.debug. Native
// syslog ships a headerless CSV carrying only the rule md5, so the label is
// unavailable there; resolving it server-side is the whole reason the log
// pipeline's firewall source uses this API path instead of syslog.
//
// Fields are exported so the internal/logship firewall source can map them onto
// structured log metadata without a second decode.
type FirewallLogRecord struct {
	// Timestamp is read_log.py's __timestamp__: the event time in the box's
	// local timezone, second resolution, with no zone suffix (e.g.
	// "2026-07-13T20:21:57").
	Timestamp string `json:"__timestamp__"`
	// Digest is the md5 of the raw log line (__digest__). It is the paging
	// cursor: passing it back as ?digest= returns every newer row plus this row
	// itself, so callers advance to the newest digest each poll and drop the
	// cursor row client-side.
	Digest string `json:"__digest__"`

	RuleNr     string `json:"rulenr"`
	SubRuleNr  string `json:"subrulenr"`
	AnchorName string `json:"anchorname"`
	// RID is the pf rule id (md5) the label is resolved from. "0" is an
	// automatic/default rule, which carries no human label.
	RID       string `json:"rid"`
	Interface string `json:"interface"`
	Reason    string `json:"reason"`
	// Action is pass | block | rdr | nat | binat.
	Action    string `json:"action"`
	Dir       string `json:"dir"`
	IPVersion string `json:"ipversion"`
	ProtoName string `json:"protoname"`
	ProtoNum  string `json:"protonum"`
	Length    string `json:"length"`
	Src       string `json:"src"`
	Dst       string `json:"dst"`
	// SrcPort/DstPort are present only for the port-bearing protocols (tcp/udp);
	// icmp/igmp/esp rows omit the key entirely — hence the schema exemption.
	SrcPort string `json:"srcport"`
	DstPort string `json:"dstport"`
	// TCPFlags is present only on tcp rows.
	TCPFlags string `json:"tcpflags"`
	// Label is the human rule description resolved from RID; empty for automatic
	// rules and for any rule without a configured description.
	Label string `json:"label"`
}

// FetchFirewallLog reads the parsed, rotation-aware firewall filter log via
// api/diagnostics/firewall/log, newest-first, capped at limit rows.
//
// When digest is non-empty the backend reverse-reads until it hits that digest
// (or exhausts the rotation window / the row cap), returning every newer row and
// the digest row itself as the oldest element — the caller drops that row and
// advances its cursor to the newest returned digest. When digest is empty it
// returns the newest limit rows. The query string is built ad hoc (like vnstat's
// get_json_data), so this request never matches the registered query-less path
// and is never served from the response cache — correct, since the feed is live.
//
// This is a core diagnostics endpoint (no plugin gate): a 404 would be a genuine
// error, so it is surfaced rather than swallowed as "feature absent".
func (c *Client) FetchFirewallLog(limit int, digest string) ([]FirewallLogRecord, *APICallError) {
	base, ok := c.endpoints["firewallLog"]
	if !ok {
		return nil, &APICallError{
			Endpoint:   "firewallLog",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	q := url.Values{}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	if digest != "" {
		q.Set("digest", digest)
	}
	path := base
	if enc := q.Encode(); enc != "" {
		path = EndpointPath(string(base) + "?" + enc)
	}

	var rows []FirewallLogRecord
	if err := c.do("GET", path, nil, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}
