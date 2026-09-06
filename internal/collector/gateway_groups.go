package collector

import (
	"context"
	"log/slog"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v5/opnsense"
)

// gatewayGroupsCollector exposes one bounded membership series for every
// gateway/group/tier tuple. The name and address labels intentionally match
// the existing gateways collector, so operators can join this family with
// opnsense_gateways_status on (name, address, opnsense_instance) and carry the
// group/tier dimensions onto the current gateway health value.
type gatewayGroupsCollector struct {
	member    *prometheus.Desc
	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &gatewayGroupsCollector{
		subsystem: GatewayGroupsSubsystem,
	})
}

func (c *gatewayGroupsCollector) Name() string { return c.subsystem }

func (c *gatewayGroupsCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.instance = instanceLabel
	log.Debug("Registering collector", "collector", c.Name())

	c.member = buildPrometheusDesc(c.subsystem, "member",
		"Gateway group membership (1) by failover group, tier, gateway name, monitor address and configured gateway address. "+
			"The name and address labels join this family to the existing gateway status metrics.",
		[]string{"group", "tier", "name", "address", "gateway_address"},
	)
}

func (c *gatewayGroupsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.member
}

func (c *gatewayGroupsCollector) Update(_ context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchGatewayGroups()
	if err != nil {
		return err
	}
	if !data.Present {
		return nil
	}

	// FetchGatewayGroups already removes duplicate members in one group/tier;
	// retain a second guard at the metric boundary in case a future normalizer
	// changes that policy or callers construct a result directly in a test.
	seen := make(map[string]bool)
	for _, group := range data.Groups {
		for _, member := range group.Members {
			if member.Name == "" {
				continue
			}
			tier := strconv.Itoa(member.Tier)
			joinAddress := gatewayStatusAddress(member.Monitor)
			key := group.Name + "\x00" + tier + "\x00" + member.Name + "\x00" + joinAddress + "\x00" + member.Address
			if seen[key] {
				continue
			}
			seen[key] = true
			ch <- prometheus.MustNewConstMetric(
				c.member,
				prometheus.GaugeValue,
				1,
				group.Name,
				tier,
				member.Name,
				joinAddress,
				member.Address,
				c.instance,
			)
		}
	}

	return nil
}
