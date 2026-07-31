package options

import (
	"fmt"
	"io"

	"github.com/alecthomas/kingpin/v2"
)

// ConfigCheck selects the side-effect-free preflight (#446): parse and validate
// the effective configuration, print the result, exit 0 or 1, and start nothing.
//
// It is a FLAG rather than a subcommand on purpose. The whole point of the
// preflight is that it runs the real parser over the real arguments and env, so
// it has to be inside the same kingpin parse the exporter itself uses — a
// subcommand would sit outside it (see the `health` probe, which is a subcommand
// precisely because it must NOT need the server's required flags).
//
// It deliberately has NO env var binding, which is the one place this flag
// departs from the project's env-driven convention. OPN2OTEL_CONFIG_CHECK
// left set in a deployment's environment would make every start validate and exit
// 0, and a container that exits 0 immediately looks like a success while serving
// nothing. Preflight is invoked by deployment tooling as an argument
// (ExecStartPre, an init container, `docker compose run`), never ambiently.
var ConfigCheck = kingpin.Flag(
	"config.check",
	"Validate the effective configuration and exit, without binding any port, starting the poll scheduler, "+
		"contacting OPNsense, or exporting telemetry. Exits 0 when the configuration is usable and 1 otherwise. "+
		"Referenced files (API key/secret, TLS keypairs) are read; network reachability is deliberately not checked "+
		"(that is what /-/ready is for). Has no env var by design: an ambient one would turn every start into a no-op.",
).Bool()

// WriteEffectiveConfig renders the resolved configuration for the preflight's
// human output.
//
// It reuses EffectiveConfig — the same builder the operator console's /config
// page uses — so the "output never includes secret contents" guarantee is
// structural rather than a promise made twice: every secret-backed row is
// reduced to a presence boolean before it reaches a renderer, and
// TestBuildEffectiveConfig_SecretsRedacted already pins that.
func WriteEffectiveConfig(w io.Writer) {
	for _, section := range EffectiveConfig() {
		fmt.Fprintf(w, "\n[%s]\n", section.Title)
		for _, item := range section.Items {
			key := item.Key
			if item.Display != "" {
				key = item.Display
			}
			fmt.Fprintf(w, "  %-28s %s\n", key, item.Value)
		}
	}
}
