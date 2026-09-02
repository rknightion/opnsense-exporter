package options

import "github.com/alecthomas/kingpin/v2"

// DefaultUDPReceiveBufferBytes is deliberately larger than the small Linux
// default (~208 KiB) that otherwise lets burst traffic disappear in the kernel
// before either receiver can account for it. The listeners read the effective
// value back and warn when the host's net.core.rmem_max clamps this request.
const DefaultUDPReceiveBufferBytes = 4 * 1024 * 1024

var (
	logsSyslogUDPReceiveBuffer = kingpin.Flag(
		"logs.syslog.udp-receive-buffer-bytes",
		"Requested kernel receive-buffer size for the syslog UDP listener, in bytes. The operating system may clamp this value; on Linux raise net.core.rmem_max when the startup warning reports a smaller effective buffer. 0 uses the built-in default.",
	).Envar("OPN2OTEL_LOGS_SYSLOG_UDP_RECEIVE_BUFFER_BYTES").Default("4194304").Int()

	flowNetflowUDPReceiveBuffer = kingpin.Flag(
		"flow.netflow.udp-receive-buffer-bytes",
		"Requested kernel receive-buffer size for the NetFlow UDP listener, in bytes. The operating system may clamp this value; on Linux raise net.core.rmem_max when the startup warning reports a smaller effective buffer. 0 uses the built-in default.",
	).Envar("OPN2OTEL_FLOW_NETFLOW_UDP_RECEIVE_BUFFER_BYTES").Default("4194304").Int()
)

// LogsSyslogUDPReceiveBufferBytes returns the requested syslog UDP receive
// buffer size. A zero value resolves to the built-in default, while a negative
// value is preserved for the caller's validation error. A caller that reads the
// option before kingpin.Parse therefore sees the same value as a parsed
// invocation with no override.
func LogsSyslogUDPReceiveBufferBytes() int {
	if *logsSyslogUDPReceiveBuffer == 0 {
		return DefaultUDPReceiveBufferBytes
	}
	return *logsSyslogUDPReceiveBuffer
}

// FlowNetflowUDPReceiveBufferBytes returns the requested NetFlow UDP receive
// buffer size. A zero value resolves to the built-in default, while a negative
// value is preserved for the caller's validation error. A caller that reads the
// option before kingpin.Parse therefore sees the same value as a parsed
// invocation with no override.
func FlowNetflowUDPReceiveBufferBytes() int {
	if *flowNetflowUDPReceiveBuffer == 0 {
		return DefaultUDPReceiveBufferBytes
	}
	return *flowNetflowUDPReceiveBuffer
}
