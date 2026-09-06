package collector

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/promslog"
	"github.com/rknightion/opnsense2otel/v5/opnsense"
)

func TestKeaCollector_EmitReservationMetrics(t *testing.T) {
	c := &keaCollector{subsystem: KeaSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	ch := make(chan prometheus.Metric, 2)
	c.emitReservationMetrics(ch, c.dhcp4Reservations, []opnsense.KeaReservation{
		// These represent configured reservations, not issued lease rows. The
		// two unclaimed reservations share one configured subnet deliberately.
		{SubnetUUID: "v4-a"},
		{SubnetUUID: "v4-a"},
		{SubnetUUID: "v4-b"},
	}, []opnsense.KeaSubnet{
		{UUID: "v4-a", Subnet: "10.23.0.0/24"},
		{UUID: "v4-b", Subnet: "10.24.0.0/24"},
	})
	close(ch)

	got := map[string]float64{}
	for metric := range ch {
		if !hasFqName(metric, "opnsense_kea_dhcp4_reservations_configured") {
			t.Errorf("unexpected metric %s", metric.Desc())
			continue
		}
		labels := getMetricLabels(metric)
		if labels["opnsense_instance"] != "test" {
			t.Errorf("instance label = %q, want test", labels["opnsense_instance"])
		}
		got[labels["subnet"]] = getMetricValue(metric)
	}
	if len(got) != 2 || got["10.23.0.0/24"] != 2 || got["10.24.0.0/24"] != 1 {
		t.Errorf("reservation metrics = %#v, want configured counts by subnet", got)
	}
}

func TestKeaCollector_EmitReservationMetrics_Empty(t *testing.T) {
	c := &keaCollector{subsystem: KeaSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	ch := make(chan prometheus.Metric, 1)
	c.emitReservationMetrics(ch, c.dhcp6Reservations, nil, []opnsense.KeaSubnet{
		{UUID: "v6-a", Subnet: "fd23::/64"},
	})
	close(ch)
	if metric, ok := <-ch; ok {
		t.Errorf("empty inventory emitted unexpected metric %s", metric.Desc())
	}
}
