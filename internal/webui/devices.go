package webui

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/rknightion/opnsense-exporter/opnsense"
)

// init registers the devices page area's routes. See server.go's extension docs
// for the pattern every page area follows.
func init() { registerRoutes((*Server).registerDevices) }

// registerDevices mounts the connected-devices JSON endpoint. Devices are a tab
// on the single console page that loads THIS endpoint lazily on tab-open — never
// on the auto-refresh poll — because the fetch is a live firewall read (ARP/DHCP
// only, never the metric collectors, so it does not trigger a scrape).
func (s *Server) registerDevices(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/devices.json", s.handleDevicesJSON)
}

func (s *Server) handleDevicesJSON(w http.ResponseWriter, r *http.Request) {
	if s.deps.DisableDevices {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, s.devicesReport(r.Context()))
}

// devicesView is the render envelope for the devices page: the report plus an
// error string when the fetch failed (rendered as an inline callout rather than
// a hard error, so a transient API blip doesn't take the page down).
type devicesView struct {
	Report DeviceReport
	Error  string
}

// devicesReport fetches the report and folds any error into the view so the
// template always renders (empty table + a callout on failure).
func (s *Server) devicesReport(ctx context.Context) devicesView {
	if s.deps.Devices == nil {
		return devicesView{}
	}
	rep, err := s.deps.Devices(ctx)
	if err != nil {
		return devicesView{Report: rep, Error: err.Error()}
	}
	return devicesView{Report: rep}
}

// FetchDevices reads the ARP table plus the DHCPv4/DHCPv6 leases from the
// firewall and merges them into a single connected-devices report. Each
// FetchArpTable/FetchDHCPv4Leases/FetchDHCPv6Leases call returns a typed
// *opnsense.APICallError; each is guarded inside its own nil-check so a nil
// *APICallError never becomes a non-nil error interface.
func FetchDevices(ctx context.Context, c *opnsense.Client) (DeviceReport, error) {
	cc := c.WithContext(ctx)
	arp, apiErr := cc.FetchArpTable()
	if apiErr != nil {
		return DeviceReport{}, apiErr
	}
	d4, apiErr := cc.FetchDHCPv4Leases()
	if apiErr != nil {
		return DeviceReport{}, apiErr
	}
	d6, apiErr := cc.FetchDHCPv6Leases()
	if apiErr != nil {
		return DeviceReport{}, apiErr
	}
	return DeviceReport{Devices: mergeDevices(arp, d4, d6), Generated: time.Now()}, nil
}

// mergeDevices folds the ARP table and the DHCPv4/DHCPv6 leases into one row
// per device, deduped by IP+MAC. ARP is applied first (it carries the lease
// expiry); a DHCP lease for the same IP+MAC merges in, and a non-empty DHCP
// hostname wins over ARP's. The manufacturer is resolved from the MAC OUI.
// Rows are sorted by IP then MAC for a stable render.
func mergeDevices(arp opnsense.ArpTable, d4 opnsense.DHCPv4Leases, d6 opnsense.DHCPv6Leases) []DeviceRow {
	idx := make(map[string]int)
	var rows []DeviceRow

	key := func(ip, mac string) string {
		return strings.ToUpper(strings.TrimSpace(ip) + "|" + strings.TrimSpace(mac))
	}

	// upsert merges r into an existing row (same IP+MAC) or appends it. fromDHCP
	// marks a DHCP-sourced hostname, which is preferred over an ARP one.
	upsert := func(r DeviceRow, fromDHCP bool) {
		if r.IP == "" && r.MAC == "" {
			return
		}
		k := key(r.IP, r.MAC)
		if i, ok := idx[k]; ok {
			ex := &rows[i]
			if r.Hostname != "" && (fromDHCP || ex.Hostname == "") {
				ex.Hostname = r.Hostname
			}
			if ex.Interface == "" {
				ex.Interface = r.Interface
			}
			if ex.Expiry == "" {
				ex.Expiry = r.Expiry
			}
			if ex.Manufacturer == "" {
				ex.Manufacturer = r.Manufacturer
			}
			return
		}
		idx[k] = len(rows)
		rows = append(rows, r)
	}

	for _, a := range arp.Arp {
		upsert(DeviceRow{
			IP:           a.IP,
			MAC:          a.Mac,
			Hostname:     a.Hostname,
			Interface:    a.IntfDescription,
			Expiry:       formatExpiry(a.Expires),
			Manufacturer: LookupOUI(a.Mac),
			Source:       "arp",
		}, false)
	}

	for _, l := range d4.Leases {
		upsert(DeviceRow{
			IP:           l.Address,
			MAC:          l.MAC,
			Hostname:     l.Hostname,
			Interface:    l.IfDescr,
			Manufacturer: LookupOUI(l.MAC),
			Source:       "dhcp4",
		}, true)
	}

	for _, l := range d6.Leases {
		// DHCPv6 leases carry no hostname (DUID replaces it upstream).
		upsert(DeviceRow{
			IP:           l.Address,
			MAC:          l.MAC,
			Interface:    l.IfDescr,
			Manufacturer: LookupOUI(l.MAC),
			Source:       "dhcp6",
		}, true)
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].IP != rows[j].IP {
			return rows[i].IP < rows[j].IP
		}
		return rows[i].MAC < rows[j].MAC
	})
	return rows
}

// formatExpiry renders an ARP lease-expiry epoch as a UTC RFC3339 timestamp. A
// zero/negative epoch (permanent or unset) renders as an empty string.
func formatExpiry(epoch int) string {
	if epoch <= 0 {
		return ""
	}
	return time.Unix(int64(epoch), 0).UTC().Format(time.RFC3339)
}
