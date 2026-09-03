package configsnapshot

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

type fakeSecurityPostureFetcher struct {
	posture opnsense.SecurityPosture
	err     *opnsense.APICallError
}

func (f *fakeSecurityPostureFetcher) FetchSecurityPosture(context.Context) (opnsense.SecurityPosture, *opnsense.APICallError) {
	return f.posture, f.err
}

func TestSecurityPostureProvider_AggregatesFirmwareCertificatesAndOwners(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	fetcher := &fakeSecurityPostureFetcher{posture: opnsense.SecurityPosture{
		Firmware: opnsense.FirmwareStatus{
			CheckPresent: true,
			Connection:   "ok",
			Repository:   "revoked",
			NeedsReboot:  true,
			UpgradePackageDetails: []opnsense.FirmwarePackageUpgrade{
				{Name: "zlib", CurrentVersion: "1.3.0", NewVersion: "1.3.1"},
				{Name: "curl", CurrentVersion: "8.8.0", NewVersion: "8.9.1"},
			},
		},
		Certificates: opnsense.CertificateStatus{Certificates: []opnsense.Certificate{
			{HasValidTo: true, ValidTo: float64(now.Add(-time.Hour).Unix())},
			{HasValidTo: true, ValidTo: float64(now.Add(7 * 24 * time.Hour).Unix())},
			{HasValidTo: true, ValidTo: float64(now.Add(31 * 24 * time.Hour).Unix())},
			{HasValidTo: false},
		}},
		APIKeyOwners:     []opnsense.APIKeyOwner{{Owner: "ops", Count: 2}, {Owner: "audit", Count: 1}},
		ListeningSockets: 2,
	}}
	provider := securityPostureProvider{client: fetcher, now: func() time.Time { return now }}

	entities, err := provider.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(entities) != 1 || entities[0].ID != "posture" {
		t.Fatalf("entities = %#v, want one posture entity", entities)
	}
	encoded, err := json.Marshal(entities[0].Value)
	if err != nil {
		t.Fatalf("marshal entity: %v", err)
	}
	var got struct {
		Firmware struct {
			Connection      string                          `json:"connection"`
			Repository      string                          `json:"repository"`
			UpgradePackages []securityPosturePackageVersion `json:"upgrade_packages"`
		} `json:"firmware"`
		CertificateExpiry securityPostureCertificateExpiry `json:"certificate_expiry"`
		APIKeyOwners      []securityPostureAPIKeyOwner     `json:"key_owners"`
		ListeningSockets  int                              `json:"listening_sockets"`
	}
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatalf("unmarshal entity: %v", err)
	}
	if got.Firmware.Connection != "ok" || got.Firmware.Repository != "revoked" {
		t.Errorf("firmware verdict = %q/%q, want ok/revoked", got.Firmware.Connection, got.Firmware.Repository)
	}
	if len(got.Firmware.UpgradePackages) != 2 || got.Firmware.UpgradePackages[0].Name != "curl" {
		t.Errorf("upgrade packages = %#v, want name-sorted package versions", got.Firmware.UpgradePackages)
	}
	if expiry := got.CertificateExpiry; expiry.Total != 4 || expiry.ValidToKnown != 3 || expiry.Expired != 1 || expiry.ExpiringWithin30Days != 1 || expiry.EarliestValidToUnix == nil {
		t.Errorf("certificate expiry = %#v, want roll-up of known/expired/30d dates", expiry)
	}
	if len(got.APIKeyOwners) != 2 || got.APIKeyOwners[0].Owner != "audit" || got.APIKeyOwners[1].Count != 2 {
		t.Errorf("API key owners = %#v, want owner-sorted aggregates", got.APIKeyOwners)
	}
	if got.ListeningSockets != 2 {
		t.Errorf("listening sockets = %d, want 2", got.ListeningSockets)
	}
}

func TestSecurityPostureProvider_RedactsNestedConfigurationMaps(t *testing.T) {
	value := map[string]any{
		"safe":    "retained",
		"api-key": "removed",
		"nested": map[string]any{
			"privateKey": "removed",
			"safe":       "retained",
		},
		"items": []any{map[string]any{"psk": "removed", "safe": "retained"}},
	}
	redactSecurityPostureConfig(value)
	if _, ok := value["api-key"]; ok {
		t.Fatal("top-level API key survived redaction")
	}
	nested := value["nested"].(map[string]any)
	if _, ok := nested["privateKey"]; ok {
		t.Fatal("nested private key survived redaction")
	}
	item := value["items"].([]any)[0].(map[string]any)
	if _, ok := item["psk"]; ok {
		t.Fatal("array-nested PSK survived redaction")
	}
	if value["safe"] != "retained" || nested["safe"] != "retained" || item["safe"] != "retained" {
		t.Fatalf("redaction removed a safe field: %#v", value)
	}
}

func TestSecurityPostureSource_DeduplicatesAndUsesWeeklyHeartbeat(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	fetcher := &fakeSecurityPostureFetcher{posture: opnsense.SecurityPosture{
		Firmware:     opnsense.FirmwareStatus{CheckPresent: true, Connection: "ok", Repository: "ok"},
		Certificates: opnsense.CertificateStatus{},
	}}
	provider := securityPostureProvider{client: fetcher, now: func() time.Time { return now }}
	batch := 0
	s := newSource([]Provider{provider}, func() time.Time { return now }, func() string {
		batch++
		return "snapshot-" + string(rune('0'+batch))
	})

	first, err := s.Poll(context.Background())
	if err != nil || len(first) != 1 || first[0].Attributes["snapshot.reason"] != "change" {
		t.Fatalf("first Poll = %#v, %v; want change record", first, err)
	}
	now = now.Add(securityPostureHeartbeat - time.Hour)
	unchanged, err := s.Poll(context.Background())
	if err != nil || len(unchanged) != 0 {
		t.Fatalf("pre-heartbeat Poll = %#v, %v; want no record", unchanged, err)
	}
	now = now.Add(time.Hour)
	heartbeat, err := s.Poll(context.Background())
	if err != nil || len(heartbeat) != 1 || heartbeat[0].Attributes["snapshot.reason"] != "heartbeat" {
		t.Fatalf("weekly Poll = %#v, %v; want heartbeat record", heartbeat, err)
	}
	fetcher.posture.Firmware.Repository = "revoked"
	now = now.Add(time.Minute)
	changed, err := s.Poll(context.Background())
	if err != nil || len(changed) != 1 || changed[0].Attributes["snapshot.reason"] != "change" {
		t.Fatalf("changed Poll = %#v, %v; want change record", changed, err)
	}
}

func TestSecurityPostureProvider_HeartbeatIsSevenDays(t *testing.T) {
	if got := (securityPostureProvider{}).Heartbeat(); got != 7*24*time.Hour {
		t.Errorf("Heartbeat() = %s, want 7d", got)
	}
}
