package syslog

import (
	"net/netip"
	"time"

	"github.com/rknightion/opnsense2otel/v5/internal/flow"
	"github.com/rknightion/opnsense2otel/v5/internal/logship"
)

// filterlogDomainObserver is the optional root-owned metric seam for resolved
// filterlog domains. The domain is passed as a metric observation only after a
// cache hit; it is never promoted into a Loki stream/resource label here.
type filterlogDomainObserver interface {
	ObserveFilterlogDomain(domain string) bool
}

func observeFilterlogDomain(sink logship.MetricSink, domain string) bool {
	observer, ok := sink.(filterlogDomainObserver)
	if !ok {
		return false
	}
	return observer.ObserveFilterlogDomain(domain)
}

// enrichFilterlogDomain joins one successfully parsed filterlog record against
// the shared flow DNS answer cache. DNSCache.Lookup is the entire hot-path
// operation: there is no resolver, API call, or miss callback. The cache key is
// intentionally the same (src/client, dst/answer) pair used by the flow lane.
//
// The returned domain is the value that was added to the record, or empty when
// the cache is disabled, either address is malformed, the pair is absent/expired,
// or the cached name itself is empty.
func enrichFilterlogDomain(rec *logship.Record, cache *flow.DNSCache, now time.Time) string {
	if rec == nil || cache == nil {
		return ""
	}

	src, err := netip.ParseAddr(rec.Attributes["src.ip"])
	if err != nil {
		return ""
	}
	dst, err := netip.ParseAddr(rec.Attributes["dst.ip"])
	if err != nil {
		return ""
	}

	domain, ok := cache.Lookup(src, dst, now)
	if !ok || domain == "" {
		return ""
	}
	if rec.Attributes == nil {
		rec.Attributes = make(map[string]string, 1)
	}
	rec.Attributes["dst.domain"] = domain
	return domain
}
