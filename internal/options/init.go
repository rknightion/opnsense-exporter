package options

import (
	"os"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus/common/promslog/flag"
)

var flagsRegistered bool

// RegisterAllFlags registers the flags that are not declared at package init
// time (currently the promslog --log.* flags) on kingpin.CommandLine. It is
// idempotent so that both Init and scripts/docgen can call it.
func RegisterAllFlags() {
	if flagsRegistered {
		return
	}
	flagsRegistered = true
	flag.AddFlags(kingpin.CommandLine, PromLogConfig)
}

func Init() {
	RegisterAllFlags()
	kingpin.CommandLine.UsageWriter(os.Stdout)
	kingpin.HelpFlag.Short('h')
	kingpin.EnableFileExpansion = true
	kingpin.Parse()
}
