package options

import (
	"fmt"
	"os"

	"go.yaml.in/yaml/v2"
)

// webTLSServerConfigForValidation mirrors just the two exporter-toolkit
// tls_server_config fields this guard needs. It is a deliberately narrow read
// of the --web.config.file YAML (full shape: vendor/github.com/prometheus/
// exporter-toolkit/web/tls_config.go's Config/TLSConfig): the toolkit is
// vendored and off-limits to hand-edit, so this repo validates its own
// configuration input before that file ever reaches the toolkit's parser.
type webTLSServerConfigForValidation struct {
	ClientAuth        string   `yaml:"client_auth_type"`
	ClientAllowedSans []string `yaml:"client_allowed_sans"`
}

type webConfigForValidation struct {
	TLSServerConfig webTLSServerConfigForValidation `yaml:"tls_server_config"`
}

// clientAuthTypesRequiringCert lists the exporter-toolkit client_auth_type
// values (see the switch in tls_config.go) whose TLS handshake cannot
// complete without the peer presenting a certificate. Every other accepted
// value --- the empty string, "NoClientCert", "RequestClientCert", and
// "VerifyClientCertIfGiven" --- lets a handshake complete with zero client
// certificates.
var clientAuthTypesRequiringCert = map[string]bool{
	"RequireAnyClientCert":       true,
	"RequireClientCert":          true, // legacy alias, preserved by exporter-toolkit for backwards compatibility
	"RequireAndVerifyClientCert": true,
}

// ValidateWebTLSConfig rejects a --web.config.file that combines
// client_allowed_sans with a client_auth_type that does not require the peer
// to present a certificate.
//
// Why this exists (#562): the vendored exporter-toolkit (v0.17.1) installs a
// VerifyPeerCertificate callback whenever client_allowed_sans is set
// (web/tls_config.go:266-269), and that callback indexes rawCerts[0] without
// checking the slice is non-empty (web/tls_config.go:100-104). NoClientCert,
// RequestClientCert, and VerifyClientCertIfGiven all allow a handshake to
// complete with no client certificate at all, so any peer reaching the
// metrics listener could trigger an index-out-of-range panic during the TLS
// handshake. net/http recovers per-connection (see net/http's conn.serve
// defer), so the direct effect is a failed connection plus a logged stack
// trace rather than a process crash --- but it is still an unauthenticated
// remote panic trigger, and vendor/ is sync-only (never hand-edited in this
// repo, see AGENTS.md), so the callback itself cannot be patched locally.
// Refuse the unsafe combination at startup instead, before it can ever reach
// a handshake.
//
// An empty path or a file this function cannot read/parse is a no-op: it is
// always called alongside web.Validate, which already surfaces those
// failures with its own error, and duplicating that here would just produce
// a second, less specific error for the same problem.
func ValidateWebTLSConfig(path string) error {
	if path == "" {
		return nil
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var cfg webConfigForValidation
	if err := yaml.Unmarshal(content, &cfg); err != nil {
		return nil
	}

	tlsCfg := cfg.TLSServerConfig
	if len(tlsCfg.ClientAllowedSans) == 0 {
		return nil
	}
	if clientAuthTypesRequiringCert[tlsCfg.ClientAuth] {
		return nil
	}

	authDisplay := tlsCfg.ClientAuth
	if authDisplay == "" {
		authDisplay = "NoClientCert (the default when client_auth_type is unset)"
	}
	return fmt.Errorf(
		"--web.config.file %q: tls_server_config.client_allowed_sans is set but "+
			"client_auth_type is %q, which lets a TLS handshake complete without the "+
			"client presenting any certificate at all; exporter-toolkit's SAN check runs "+
			"during that handshake regardless and panics on a certificate-less client. "+
			"Set client_auth_type to RequireAnyClientCert or RequireAndVerifyClientCert, "+
			"or remove client_allowed_sans",
		path, authDisplay,
	)
}
