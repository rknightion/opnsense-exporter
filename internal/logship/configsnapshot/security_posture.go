package configsnapshot

import (
	"context"
	"sort"
	"time"

	"github.com/rknightion/opnsense2otel/v5/opnsense"
)

const securityPostureHeartbeat = 7 * 24 * time.Hour

type securityPostureFetcher interface {
	FetchSecurityPosture(context.Context) (opnsense.SecurityPosture, *opnsense.APICallError)
}

type opnsenseSecurityPostureFetcher struct{ client *opnsense.Client }

func (f opnsenseSecurityPostureFetcher) FetchSecurityPosture(ctx context.Context) (opnsense.SecurityPosture, *opnsense.APICallError) {
	return f.client.WithContext(ctx).FetchSecurityPosture()
}

// securityPostureProvider turns the current security-relevant configuration
// state into one bounded logical entity.
type securityPostureProvider struct {
	client securityPostureFetcher
	now    func() time.Time
}

func (securityPostureProvider) Family() string { return "security_posture" }

func (securityPostureProvider) Heartbeat() time.Duration { return securityPostureHeartbeat }

func (p securityPostureProvider) Snapshot(ctx context.Context) ([]Entity, error) {
	posture, err := p.client.FetchSecurityPosture(ctx)
	if err != nil {
		return nil, err
	}
	now := time.Now
	if p.now != nil {
		now = p.now
	}

	entity := map[string]any{
		"firmware": securityPostureFirmware{
			CheckPresent:          posture.Firmware.CheckPresent,
			Connection:            posture.Firmware.Connection,
			Repository:            posture.Firmware.Repository,
			NeedsReboot:           posture.Firmware.NeedsReboot,
			UpgradeNeedsReboot:    posture.Firmware.UpgradeNeedsReboot,
			MajorUpgradeAvailable: posture.Firmware.MajorUpgradeAvailable,
			MajorUpgradeVersion:   posture.Firmware.MajorUpgradeVersion,
			UpgradePackages:       securityPosturePackageVersions(posture.Firmware.UpgradePackageDetails),
		},
		"certificate_expiry": securityPostureCertificateExpirySummary(posture.Certificates, now().UTC()),
		// The shared redactor treats key terms as sensitive; use the
		// enclosing posture schema to give this safe aggregate its meaning.
		"access_owners":     securityPostureAPIKeyOwners(posture.APIKeyOwners),
		"listening_sockets": posture.ListeningSockets,
	}
	// Keep this call immediately before Entity construction: configuration-shaped
	// maps must be redacted before source.recordBody can consider truncation.
	redactSecurityPostureConfig(entity)
	return []Entity{{ID: "posture", Value: entity}}, nil
}

type securityPostureFirmware struct {
	CheckPresent          bool                            `json:"check_present"`
	Connection            string                          `json:"connection,omitempty"`
	Repository            string                          `json:"repository,omitempty"`
	NeedsReboot           bool                            `json:"needs_reboot"`
	UpgradeNeedsReboot    bool                            `json:"upgrade_needs_reboot"`
	MajorUpgradeAvailable bool                            `json:"major_upgrade_available"`
	MajorUpgradeVersion   string                          `json:"major_upgrade_version,omitempty"`
	UpgradePackages       []securityPosturePackageVersion `json:"upgrade_packages"`
}

type securityPosturePackageVersion struct {
	Name           string `json:"name"`
	CurrentVersion string `json:"current_version"`
	NewVersion     string `json:"new_version"`
}

func securityPosturePackageVersions(packages []opnsense.FirmwarePackageUpgrade) []securityPosturePackageVersion {
	out := make([]securityPosturePackageVersion, 0, len(packages))
	for _, pkg := range packages {
		out = append(out, securityPosturePackageVersion{
			Name:           pkg.Name,
			CurrentVersion: pkg.CurrentVersion,
			NewVersion:     pkg.NewVersion,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		if out[i].CurrentVersion != out[j].CurrentVersion {
			return out[i].CurrentVersion < out[j].CurrentVersion
		}
		return out[i].NewVersion < out[j].NewVersion
	})
	return out
}

type securityPostureCertificateExpiry struct {
	Total                int      `json:"total"`
	ValidToKnown         int      `json:"valid_to_known"`
	Expired              int      `json:"expired"`
	ExpiringWithin30Days int      `json:"expiring_within_30_days"`
	EarliestValidToUnix  *float64 `json:"earliest_valid_to_unix,omitempty"`
}

func securityPostureCertificateExpirySummary(certificates opnsense.CertificateStatus, now time.Time) securityPostureCertificateExpiry {
	result := securityPostureCertificateExpiry{Total: len(certificates.Certificates)}
	deadline := now.Add(30 * 24 * time.Hour).Unix()
	for _, certificate := range certificates.Certificates {
		if !certificate.HasValidTo {
			continue
		}
		result.ValidToKnown++
		if result.EarliestValidToUnix == nil || certificate.ValidTo < *result.EarliestValidToUnix {
			validTo := certificate.ValidTo
			result.EarliestValidToUnix = &validTo
		}
		if certificate.ValidTo <= float64(now.Unix()) {
			result.Expired++
		} else if certificate.ValidTo <= float64(deadline) {
			result.ExpiringWithin30Days++
		}
	}
	return result
}

type securityPostureAPIKeyOwner struct {
	Owner string `json:"owner"`
	Count int    `json:"count"`
}

func securityPostureAPIKeyOwners(owners []opnsense.APIKeyOwner) []securityPostureAPIKeyOwner {
	out := make([]securityPostureAPIKeyOwner, 0, len(owners))
	for _, owner := range owners {
		out = append(out, securityPostureAPIKeyOwner{Owner: owner.Owner, Count: owner.Count})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Owner < out[j].Owner })
	return out
}

// redactSecurityPostureConfig recursively removes sensitive fields from maps
// before the snapshot framework serializes or truncates their bodies. It uses
// the shared OPNsense vocabulary so configuration snapshots cannot diverge in
// their handling of a newly discovered secret key.
func redactSecurityPostureConfig(value any) {
	switch value := value.(type) {
	case map[string]any:
		for key, child := range value {
			if opnsense.SensitiveConfigKey(key) {
				delete(value, key)
				continue
			}
			redactSecurityPostureConfig(child)
		}
	case []any:
		for _, child := range value {
			redactSecurityPostureConfig(child)
		}
	}
}
