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

	shellWarningUsers   *prometheus.Desc
	oldestPasswordAge   *prometheus.Desc
	unknownPasswordAges *prometheus.Desc

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
		"Number of local users, by disabled state (aggregate count only - no usernames are exposed).",
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
		"Number of local users with a TOTP seed configured (aggregate count only - the seed itself is never read into exporter memory beyond a transient presence check).",
		nil,
	)
	c.apiKeys = buildPrometheusDesc(c.subsystem, "api_keys",
		"Total number of local-user API keys configured (aggregate count only - key material is never decoded).",
		nil,
	)
	c.groups = buildPrometheusDesc(c.subsystem, "groups",
		"Total number of local authentication groups configured.",
		nil,
	)

	// #583. Named after OPNsense's own shell_warning flag rather than the
	// "insecure shell" the issue proposed, because that names the wrong
	// property: upstream computes the flag as
	// strpos(shell,'/')===0 && empty(is_admin) (Auth/Api/UserController.php:121),
	// so it fires on ANY real login shell held by a NON-admin and never on an
	// administrator, whatever shell they have.
	c.shellWarningUsers = buildPrometheusDesc(c.subsystem, "users_shell_warning",
		"Number of local users OPNsense flags with shell_warning: a NON-administrator account that has been given a real login shell (any shell whose path starts with /). Says nothing about which shell, and never fires for an administrator. Aggregate count only - no usernames are exposed.",
		nil,
	)
	c.oldestPasswordAge = buildPrometheusDesc(c.subsystem, "oldest_password_age_seconds",
		"Age in seconds of the least recently changed local password, across the accounts that have a recorded change time. NOT emitted at all when no account has one - a 0 would claim every password was just rotated. Read alongside users_password_age_unknown, which counts the accounts this maximum cannot see. Aggregate only - no usernames are exposed.",
		nil,
	)
	c.unknownPasswordAges = buildPrometheusDesc(c.subsystem, "users_password_age_unknown",
		"Number of local users with no usable password-change time. OPNsense records pwd_changed_at only when a password is actually changed, so this counts accounts whose password predates that bookkeeping - the worst posture on the box, and invisible in oldest_password_age_seconds. Aggregate count only - no usernames are exposed.",
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
	ch <- c.shellWarningUsers
	ch <- c.oldestPasswordAge
	ch <- c.unknownPasswordAges
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
	ch <- prometheus.MustNewConstMetric(c.shellWarningUsers, prometheus.GaugeValue,
		float64(posture.UsersWithShellWarning), c.instance)
	ch <- prometheus.MustNewConstMetric(c.unknownPasswordAges, prometheus.GaugeValue,
		float64(posture.UsersWithUnknownPasswordAge), c.instance)
	// Absent, not zero, when nothing on the box has a recorded change time.
	if posture.HasOldestPasswordAge {
		ch <- prometheus.MustNewConstMetric(c.oldestPasswordAge, prometheus.GaugeValue,
			posture.OldestPasswordAgeSeconds, c.instance)
	}

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
