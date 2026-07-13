package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

// authCollector surfaces local-authentication security-posture counts (#222):
// how many local users/groups/API keys exist, how many are disabled vs
// enabled, how many are admins, how many are expired, and how many have a TOTP
// seed configured. Every metric is a whole-population aggregate — no
// per-user/per-key/per-group labels are ever emitted, since usernames and
// group names would leak PII (and cardinality) into label values for data a
// homelab-scale local auth store gains nothing from having broken out.
type authCollector struct {
	log *slog.Logger

	usersByDisabled *prometheus.Desc
	adminUsers      *prometheus.Desc
	expiredUsers    *prometheus.Desc
	usersWithOTP    *prometheus.Desc
	apiKeys         *prometheus.Desc
	groups          *prometheus.Desc

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &authCollector{
		subsystem: AuthSubsystem,
	})
}

func (c *authCollector) Name() string {
	return c.subsystem
}

func (c *authCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	c.usersByDisabled = buildPrometheusDesc(c.subsystem, "users",
		"Number of local users, by disabled state (aggregate count only — no usernames are exposed).",
		[]string{"disabled"},
	)
	c.adminUsers = buildPrometheusDesc(c.subsystem, "admin_users",
		"Number of local users with administrator privileges (is_admin computed by OPNsense; aggregate count only).",
		nil,
	)
	c.expiredUsers = buildPrometheusDesc(c.subsystem, "users_expired",
		"Number of local users whose account expiry date is in the past (aggregate count only).",
		nil,
	)
	c.usersWithOTP = buildPrometheusDesc(c.subsystem, "users_with_otp",
		"Number of local users with a TOTP seed configured (aggregate count only — the seed itself is never read into exporter memory beyond a transient presence check).",
		nil,
	)
	c.apiKeys = buildPrometheusDesc(c.subsystem, "api_keys",
		"Total number of local-user API keys configured (aggregate count only — key material is never decoded).",
		nil,
	)
	c.groups = buildPrometheusDesc(c.subsystem, "groups",
		"Total number of local authentication groups configured.",
		nil,
	)
}

func (c *authCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.usersByDisabled
	ch <- c.adminUsers
	ch <- c.expiredUsers
	ch <- c.usersWithOTP
	ch <- c.apiKeys
	ch <- c.groups
}

func (c *authCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	posture, err := client.FetchAuthUsers()
	if err != nil {
		return err
	}

	ch <- prometheus.MustNewConstMetric(c.usersByDisabled, prometheus.GaugeValue,
		float64(posture.UsersEnabled), "false", c.instance)
	ch <- prometheus.MustNewConstMetric(c.usersByDisabled, prometheus.GaugeValue,
		float64(posture.UsersDisabled), "true", c.instance)
	ch <- prometheus.MustNewConstMetric(c.adminUsers, prometheus.GaugeValue,
		float64(posture.AdminUsers), c.instance)
	ch <- prometheus.MustNewConstMetric(c.expiredUsers, prometheus.GaugeValue,
		float64(posture.ExpiredUsers), c.instance)
	ch <- prometheus.MustNewConstMetric(c.usersWithOTP, prometheus.GaugeValue,
		float64(posture.UsersWithOTP), c.instance)

	apiKeyCount, apiErr := client.FetchAuthAPIKeyCount()
	if apiErr != nil {
		return apiErr
	}
	ch <- prometheus.MustNewConstMetric(c.apiKeys, prometheus.GaugeValue, float64(apiKeyCount), c.instance)

	groupCount, groupErr := client.FetchAuthGroupCount()
	if groupErr != nil {
		return groupErr
	}
	ch <- prometheus.MustNewConstMetric(c.groups, prometheus.GaugeValue, float64(groupCount), c.instance)

	return nil
}
