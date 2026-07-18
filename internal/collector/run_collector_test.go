package collector

import (
	"context"
	"errors"
	"testing"

	"github.com/prometheus/common/promslog"
	"github.com/rknightion/opnsense-exporter/internal/options"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

// newRunCollectorTestClient builds a real *opnsense.Client the same way
// collector_test.go does; New(nil, ...) panics because it calls c.Client.Endpoints().
func newRunCollectorTestClient(t *testing.T) opnsense.Client {
	t.Helper()
	conf := options.OPNSenseConfig{
		Protocol: "http",
		APIKey:   "test",
	}
	client, err := opnsense.NewClient(conf, "test", promslog.NewNopLogger())
	if err != nil {
		t.Fatalf("expected no error building client, got %v", err)
	}
	return client
}

func TestRunCollector_Unknown(t *testing.T) {
	client := newRunCollectorTestClient(t)
	c, err := New(&client, promslog.NewNopLogger(), "inst")
	if err != nil {
		t.Fatal(err)
	}
	if _, e := c.RunCollector(context.Background(), "does-not-exist"); !errors.Is(e, ErrUnknownCollector) {
		t.Fatalf("want ErrUnknownCollector, got %v", e)
	}
}
