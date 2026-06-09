package options

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/alecthomas/kingpin/v2"
)

var (
	pyroscopeServerAddress = kingpin.Flag(
		"pyroscope.server-address",
		"Grafana Cloud Pyroscope endpoint URL. When empty, continuous profiling is disabled.",
	).Envar("OPNSENSE_EXPORTER_PYROSCOPE_SERVER_ADDRESS").Default("").String()
	pyroscopeAuthUser = kingpin.Flag(
		"pyroscope.auth-user",
		"HTTP basic auth user for Pyroscope (Grafana Cloud stack/instance ID). "+
			"This flag/ENV or PYROSCOPE_AUTH_USER_FILE may be set.",
	).Envar("OPNSENSE_EXPORTER_PYROSCOPE_AUTH_USER").Default("").String()
	pyroscopeAuthPassword = kingpin.Flag(
		"pyroscope.auth-password",
		"HTTP basic auth password for Pyroscope (Grafana Cloud Access Policy token). "+
			"This flag/ENV or PYROSCOPE_AUTH_PASSWORD_FILE may be set.",
	).Envar("OPNSENSE_EXPORTER_PYROSCOPE_AUTH_PASSWORD").Default("").String()
	pyroscopeTenantID = kingpin.Flag(
		"pyroscope.tenant-id",
		"Pyroscope tenant ID (only needed for multi-tenancy; unused for Grafana Cloud).",
	).Envar("OPNSENSE_EXPORTER_PYROSCOPE_TENANT_ID").Default("").String()
	pyroscopeApplicationName = kingpin.Flag(
		"pyroscope.application-name",
		"Pyroscope application name profiles are reported under.",
	).Envar("OPNSENSE_EXPORTER_PYROSCOPE_APPLICATION_NAME").Default("opnsense-exporter").String()
	pyroscopeEnableMutexBlock = kingpin.Flag(
		"pyroscope.enable-mutex-block",
		"Enable goroutine/mutex/block profiling (adds minor runtime overhead).",
	).Envar("OPNSENSE_EXPORTER_PYROSCOPE_ENABLE_MUTEX_BLOCK").Default("false").Bool()
)

// PyroscopeConfig holds the configuration for continuous profiling.
type PyroscopeConfig struct {
	ServerAddress    string
	AuthUser         string
	AuthPassword     string
	TenantID         string
	ApplicationName  string
	EnableMutexBlock bool
}

// Validate checks that a profiling configuration is complete: every field
// required to start the profiler must be set. Enablement is decided separately
// by Pyroscope (an empty server address means "disabled"); Validate is only
// reached for configs that are meant to be enabled.
func (c *PyroscopeConfig) Validate() error {
	if c.ServerAddress == "" {
		return fmt.Errorf("pyroscope server address must be set")
	}
	if c.AuthUser == "" {
		return fmt.Errorf("pyroscope auth-user must be set when server address is configured")
	}
	if c.AuthPassword == "" {
		return fmt.Errorf("pyroscope auth-password must be set when server address is configured")
	}
	if c.ApplicationName == "" {
		return fmt.Errorf("pyroscope application-name must be set")
	}
	return nil
}

// resolveSecret returns the value from the file named by fileEnvVar when that
// env var is set and the file's first line is non-empty; otherwise it returns
// flagValue. Mirrors the OPS_API_*_FILE precedence in ops.go.
func resolveSecret(fileEnvVar, flagValue string) (string, error) {
	if path, ok := os.LookupEnv(fileEnvVar); ok && path != "" {
		v, err := getLineFromFile(path)
		if err != nil {
			return "", errors.Join(fmt.Errorf("failed to read %s", fileEnvVar), err)
		}
		if v != "" {
			return v, nil
		}
	}
	return flagValue, nil
}

// Pyroscope assembles the profiling configuration. The returned bool reports
// whether profiling is enabled (true only when a server address is set). When
// enabled, the returned config is validated.
func Pyroscope() (*PyroscopeConfig, bool, error) {
	addr := strings.TrimSpace(*pyroscopeServerAddress)
	if addr == "" {
		return nil, false, nil
	}

	user, err := resolveSecret("PYROSCOPE_AUTH_USER_FILE", *pyroscopeAuthUser)
	if err != nil {
		return nil, false, err
	}
	password, err := resolveSecret("PYROSCOPE_AUTH_PASSWORD_FILE", *pyroscopeAuthPassword)
	if err != nil {
		return nil, false, err
	}

	cfg := &PyroscopeConfig{
		ServerAddress:    addr,
		AuthUser:         strings.TrimSpace(user),
		AuthPassword:     strings.TrimSpace(password),
		TenantID:         strings.TrimSpace(*pyroscopeTenantID),
		ApplicationName:  strings.TrimSpace(*pyroscopeApplicationName),
		EnableMutexBlock: *pyroscopeEnableMutexBlock,
	}

	if err := cfg.Validate(); err != nil {
		return nil, false, err
	}
	return cfg, true, nil
}
