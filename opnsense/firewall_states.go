package opnsense

import (
	"strings"
)

// firewallStatesResponse is api/diagnostics/firewall/query_states.
//
// Only the fields the policy-route repair needs are modelled. The live payload
// carries twenty-three keys per row (verified against a production OPNsense
// 26.7.1_1 on 2026-07-31: age, bytes, descr, direction, dst_addr, dst_port,
// expires, flags, gateway, id, iface, interface, ipproto, label, nat_addr,
// nat_port, pkts, proto, reply-to, route-to, rule, src_addr, src_port, state);
// the rest are either identity, volume already counted by ng_netflow, or
// presentation.
//
// `route-to` is the whole point of reading this endpoint. pf sets it ONLY when a
// policy-route rule fired, formatted "<gateway>@<device>" (e.g.
// "192.0.2.1@ixl1"), so its presence is an exact discriminator: a state without
// it followed the FIB, which is precisely the case where ng_netflow's
// OUTPUT_SNMP is already right (#603).
//
// `nat_addr`/`nat_port` are the second reason (#623). They appear on the
// direction="out" row and hold the PRE-NAT endpoint of the translation, so the
// pair (src_addr:src_port -> nat_addr:nat_port) is pf's own NAT mapping, stated
// rather than inferred. That is what lets the flow lane recognise the post-NAT
// copy of a conversation as the same conversation as its pre-NAT copy. Both are
// null on a direction="in" row and on any state that was never translated, and
// both are therefore modelled as pointers-in-effect: the zero value means "no
// translation recorded", which is a real answer, not a missing one.
type firewallStatesResponse struct {
	Rows []struct {
		Proto     string `json:"proto"`
		Direction string `json:"direction"`
		SrcAddr   string `json:"src_addr"`
		SrcPort   string `json:"src_port"`
		DstAddr   string `json:"dst_addr"`
		DstPort   string `json:"dst_port"`
		RouteTo   string `json:"route-to"`
		NatAddr   string `json:"nat_addr"`
		NatPort   string `json:"nat_port"`
	} `json:"rows"`
	Total    int `json:"total"`
	RowCount int `json:"rowCount"`
	Current  int `json:"current"`
}

// FirewallState is one pf state, reduced to the routing decision it recorded.
//
// Direction is pf's own: "in" is the state as the packet ENTERED the firewall,
// i.e. the PRE-NAT 5-tuple, which is exactly the tuple a pre-NAT NetFlow record
// carries. "out" is the post-NAT view and is deliberately kept as well, so a
// consumer can tell the two apart rather than the fetch deciding for it.
type FirewallState struct {
	Proto     string
	Direction string
	SrcAddr   string
	SrcPort   string
	DstAddr   string
	DstPort   string
	// RouteToGateway and RouteToDevice are the two halves of pf's `route-to`.
	// Both are empty when the state carries none, which means the FIB decided.
	RouteToGateway string
	RouteToDevice  string

	// NatAddr and NatPort are the PRE-NAT endpoint pf recorded for this state,
	// present only on direction="out" rows of a translated conversation (#623).
	// Empty means no translation was recorded, which is a real answer: an
	// un-NAT'd flow has exactly one copy and nothing to de-duplicate.
	NatAddr string
	NatPort string
}

// FirewallStates is the whole state table as one snapshot.
//
// Total is the envelope's own count rather than len(States): a disagreement
// between the two is the signal that the row cap moved, and folding them into
// one number would hide it.
type FirewallStates struct {
	States []FirewallState
	Total  int
}

// fetchFirewallStatesPayload asks for the WHOLE table in one request. rowCount -1
// is bootgrid's "no limit"; measured against production this is 3.3 MB / 645 ms
// for 6,602 rows, which is why the caller polls it on the cold tier and holds the
// result as a lookup map rather than asking per flow (#603).
const fetchFirewallStatesPayload = `{"current":1,"rowCount":-1,"searchPhrase":""}`

// FetchFirewallStates reads the pf state table.
//
// This is a CORE route — every OPNsense install has it — so a 404 here is a real
// fault, not an absent plugin, and the endpoint is deliberately kept out of
// NegativeCacheable404Endpoints().
func (c *Client) FetchFirewallStates() (FirewallStates, *APICallError) {
	var resp firewallStatesResponse
	var data FirewallStates

	path, ok := c.endpoints["firewallStates"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "firewallStates",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("POST", path, strings.NewReader(fetchFirewallStatesPayload), &resp); err != nil {
		return data, err
	}

	data.Total = resp.Total
	data.States = make([]FirewallState, 0, len(resp.Rows))
	for _, row := range resp.Rows {
		st := FirewallState{
			Proto:     row.Proto,
			Direction: row.Direction,
			SrcAddr:   row.SrcAddr,
			SrcPort:   row.SrcPort,
			DstAddr:   row.DstAddr,
			DstPort:   row.DstPort,
			NatAddr:   row.NatAddr,
			NatPort:   row.NatPort,
		}
		st.RouteToGateway, st.RouteToDevice = splitRouteTo(row.RouteTo)
		data.States = append(data.States, st)
	}
	return data, nil
}

// splitRouteTo splits pf's "<gateway>@<device>" into its two halves.
//
// Anything without an "@" yields nothing at all rather than a guess about which
// half it is: the device is what the repair acts on, and attributing traffic to an
// interface named by a malformed field is exactly the class of error the repair
// exists to remove.
func splitRouteTo(v string) (gateway, device string) {
	at := strings.LastIndex(v, "@")
	if at < 0 {
		return "", ""
	}
	gateway, device = v[:at], v[at+1:]
	if device == "" {
		return "", ""
	}
	return gateway, device
}
