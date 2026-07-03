package options

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/alecthomas/kingpin/v2"
)

var (
	opnsenseProtocol = kingpin.Flag(
		"opnsense.protocol",
		"Protocol to use to connect to OPNsense API. One of: [http, https]",
	).Envar("OPNSENSE_EXPORTER_OPS_PROTOCOL").Required().String()
	opnsenseAPI = kingpin.Flag(
		"opnsense.address",
		"Hostname or IP address of OPNsense API",
	).Envar("OPNSENSE_EXPORTER_OPS_API").Required().String()
	opnsenseAPIKey = kingpin.Flag(
		"opnsense.api-key",
		"API key to use to connect to OPNsense API. This flag/ENV or the OPS_API_KEY_FILE may be set.",
	).Default("").Envar("OPNSENSE_EXPORTER_OPS_API_KEY").String()
	opnsenseAPISecret = kingpin.Flag(
		"opnsense.api-secret",
		"API secret to use to connect to OPNsense API. This flag/ENV or the OPS_API_SECRET_FILE may be set.",
	).Default("").Envar("OPNSENSE_EXPORTER_OPS_API_SECRET").String()
	opnsenseInsecure = kingpin.Flag(
		"opnsense.insecure",
		"Disable TLS certificate verification",
	).Envar("OPNSENSE_EXPORTER_OPS_INSECURE").Default("false").Bool()
	opnsenseTimeout = kingpin.Flag(
		"opnsense.timeout",
		"Per-request HTTP timeout for calls to the OPNsense API. Combined with --opnsense.max-retries this bounds the worst-case time a collector blocks on a slow endpoint (timeout x retries). Keep the product comfortably under Prometheus' scrape_timeout.",
	).Envar("OPNSENSE_EXPORTER_OPS_TIMEOUT").Default("15s").Duration()
	opnsenseMaxRetries = kingpin.Flag(
		"opnsense.max-retries",
		"Number of attempts for a failed OPNsense API request (transport errors / retryable 5xx). Worst-case block time is --opnsense.timeout x this value.",
	).Envar("OPNSENSE_EXPORTER_OPS_MAX_RETRIES").Default("3").Int()
)

// ReadFirstLine opens a file and reads its first line.
// It returns the first line as a string and any error encountered.
func getLineFromFile(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err // Return an empty string and the error
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		return strings.TrimSpace(scanner.Text()), nil
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	return "", nil
}

// opsAPISecret / opsAPIKey resolve the OPS API credentials through the shared
// resolveSecret helper, which guards against a set-but-empty *_FILE env var (a common
// templated-blank pattern) by falling back to the flag/env value instead of trying to
// open ""; the three secret families (OPS key/secret, Pyroscope/OTLP) thus share one
// precedence. A missing value is enforced later by OPNSenseConfig.Validate (#109).
func opsAPISecret() (string, error) {
	return resolveSecretMulti(*opnsenseAPISecret,
		"OPNSENSE_EXPORTER_OPS_API_SECRET_FILE", "OPS_API_SECRET_FILE")
}

func opsAPIKey() (string, error) {
	return resolveSecretMulti(*opnsenseAPIKey,
		"OPNSENSE_EXPORTER_OPS_API_KEY_FILE", "OPS_API_KEY_FILE")
}

// OPNSenseConfig holds the configuration for the OPNsense API.
type OPNSenseConfig struct {
	Protocol  string
	Host      string
	APIKey    string
	APISecret string
	Insecure  bool
	// Timeout is the per-request HTTP timeout; zero means the client default (15s).
	Timeout time.Duration
	// MaxRetries is the attempt count for a failed request; <=0 means the client
	// default (3).
	MaxRetries int
}

// Validate checks if the configuration is valid.
// returns an error on any missing value
func (c *OPNSenseConfig) Validate() error {
	if c.Protocol != "http" && c.Protocol != "https" {
		return fmt.Errorf("protocol must be one of: [http, https]")
	}
	if c.Host == "" {
		return fmt.Errorf("host must be set")
	}
	if c.APIKey == "" {
		return fmt.Errorf("api-key must be set")
	}
	if c.APISecret == "" {
		return fmt.Errorf("api-secret must be set")
	}
	return nil
}

func OPNSense() (*OPNSenseConfig, error) {
	apiKey, err := opsAPIKey()
	if err != nil {
		return nil, err
	}
	apiSecret, err := opsAPISecret()
	if err != nil {
		return nil, err
	}
	conf := &OPNSenseConfig{
		Protocol:   strings.TrimSpace(*opnsenseProtocol),
		Host:       strings.TrimSpace(*opnsenseAPI),
		APIKey:     apiKey,
		APISecret:  apiSecret,
		Insecure:   *opnsenseInsecure,
		Timeout:    *opnsenseTimeout,
		MaxRetries: *opnsenseMaxRetries,
	}

	if err := conf.Validate(); err != nil {
		return nil, err
	}

	return conf, nil
}
