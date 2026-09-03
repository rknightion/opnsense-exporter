package opnsense

import (
	"net"
	"strings"
)

// keaReservationRow is the consumed subset of one
// api/kea/dhcpv4|dhcpv6/searchReservation UIModelGrid row. Both routes use
// reservations.reservation, whose required subnet ModelRelationField stores
// the parent subnet's UUID. UIModelGrid emits that raw value as subnet and,
// because it differs from the relation description, emits %subnet as well.
//
// This shape is source-derived from OPNsense core 26.1.11 (c930ab586ffe) and
// 26.7.3 (368b814d349a): Dhcpv4Controller.php and Dhcpv6Controller.php each
// call searchBase("reservations.reservation", ...), while UIModelGrid.php
// builds raw and %description fields for every flat model node. The v4 model
// describes a subnet as its CIDR; the v6 model describes it as
// "<interface> <CIDR>". No reservation identity or attribute is modelled.
type keaReservationRow struct {
	SubnetUUID    string `json:"subnet"`
	SubnetDisplay string `json:"%subnet"`
}

type keaReservationResponse struct {
	Rows []keaReservationRow `json:"rows"`
}

// KeaReservation is a configured reservation's parent-subnet relationship.
// It deliberately contains no reservation identity, hostname, address, or
// client identifier because callers only publish aggregate subnet inventory.
type KeaReservation struct {
	SubnetUUID    string
	SubnetDisplay string
}

func (c *Client) fetchKeaReservations(endpointName EndpointName) ([]KeaReservation, *APICallError) {
	var resp keaReservationResponse

	url, ok := c.endpoints[endpointName]
	if !ok {
		return nil, &APICallError{
			Endpoint:   string(endpointName),
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	// UIModelGrid's fetchBindRequest defaults an absent rowCount to -1, its
	// all-results sentinel. Do not supply rowCount/current/search parameters:
	// a plain GET therefore returns the complete configured inventory, not a
	// bootgrid page. Source: UIModelGrid.php in core 26.1.11 and 26.7.3.
	if err := c.do("GET", url, nil, &resp); err != nil {
		return nil, err
	}

	reservations := make([]KeaReservation, 0, len(resp.Rows))
	for _, row := range resp.Rows {
		reservations = append(reservations, KeaReservation(row))
	}
	return reservations, nil
}

// FetchKeaReservations4 returns every configured Kea DHCPv4 reservation.
func (c *Client) FetchKeaReservations4() ([]KeaReservation, *APICallError) {
	return c.fetchKeaReservations("keaReservations4")
}

// FetchKeaReservations6 returns every configured Kea DHCPv6 reservation.
func (c *Client) FetchKeaReservations6() ([]KeaReservation, *APICallError) {
	return c.fetchKeaReservations("keaReservations6")
}

// KeaReservationCountsBySubnet counts configured reservations by their
// configured subnet CIDR. The UUID relationship is resolved against the
// matching searchSubnet response. If a concurrent config change makes that
// join miss, use UIModelGrid's source-produced %subnet description only when
// it contains a CIDR; never expose a UUID as a metric label.
func KeaReservationCountsBySubnet(reservations []KeaReservation, subnets []KeaSubnet) map[string]int {
	byUUID := make(map[string]string, len(subnets))
	for _, subnet := range subnets {
		if subnet.UUID != "" && subnet.Subnet != "" {
			byUUID[subnet.UUID] = subnet.Subnet
		}
	}

	counts := make(map[string]int)
	for _, reservation := range reservations {
		subnet := byUUID[reservation.SubnetUUID]
		if subnet == "" {
			subnet = keaReservationDisplayCIDR(reservation.SubnetDisplay)
		}
		if subnet != "" {
			counts[subnet]++
		}
	}
	return counts
}

func keaReservationDisplayCIDR(display string) string {
	display = strings.TrimSpace(display)
	if _, _, err := net.ParseCIDR(display); err == nil {
		return display
	}
	if idx := strings.LastIndex(display, " "); idx >= 0 {
		candidate := display[idx+1:]
		if _, _, err := net.ParseCIDR(candidate); err == nil {
			return candidate
		}
	}
	return ""
}
