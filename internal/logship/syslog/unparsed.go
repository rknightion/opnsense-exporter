package syslog

// unparsedObserver is deliberately optional at this package boundary: the
// root-owned ReceiverMetrics type gains the method as part of its receiver
// self-metric surface, while source/package tests and downstream users of the
// existing MetricSink interface remain source-compatible (#0037).
type unparsedObserver interface {
	Unparsed(subsystem string)
}

// observeUnparsed records a parser-coverage miss on ReceiverMetrics when the
// root package has the new self-metric method. Accepting an interface value here
// keeps this lane buildable against the pre-OPN-0037 root package while making
// the required method seam explicit to the integration owner.
func observeUnparsed(metrics any, subsystem string) bool {
	observer, ok := metrics.(unparsedObserver)
	if !ok {
		return false
	}
	observer.Unparsed(subsystem)
	return true
}
