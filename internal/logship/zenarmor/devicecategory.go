package zenarmor

// zenDeviceCategories is the closed device-category vocabulary, in the same explicit-map
// shape as zenAlertSeverities.
//
// It matters more than the other clamps because this value is the only one of them that
// becomes a Loki INDEX LABEL (logship.AttrDeviceCategory, hoisted onto the OTLP resource
// by the sink — see shape_attrs.go). Zenarmor arrives over a push receiver, so the value
// is whatever the sender wrote; unclamped, one misbehaving or hostile sender mints a Loki
// stream per invented category, and every stream is permanent.
//
// The list is LIVE-MEASURED, not transcribed from a vendor document we have not read. It
// is every value observed on the real box across five one-hour probes spanning 24 hours
// (2026-07-27, #473). Deliberately not padded with plausible-sounding extras: a category
// this exporter has never seen is exactly the case the `other` fold exists for, and
// inventing taxonomy members would encode a shape upstream may not produce.
//
// `other` is Zenarmor's OWN unclassified bucket, which is why folding into it is
// semantically honest rather than a dumping ground — an unrecognised category and a
// category Zenarmor itself could not classify mean the same thing to a query.
//
// Adding a value here widens a resource-key dimension, so it means re-checking
// maxLogResources against observedResourceCombos in the sink.
var zenDeviceCategories = map[string]string{
	"camera":     "camera",
	"iot":        "iot",
	"laptop":     "laptop",
	"mobile":     "mobile",
	"multimedia": "multimedia",
	"network":    "network",
	"other":      "other",
	"printer":    "printer",
	"server":     "server",
}

// clampDeviceCategory folds a device category to the label vocabulary. Empty stays
// empty: "this document carried no device" — every syslog record, and any Zenarmor
// document Zenarmor could not attribute — must stay distinguishable from "carried
// something we do not recognise". An empty string would otherwise read as a real value
// in LogQL and pool both cases into one meaningless stream.
func clampDeviceCategory(v string) string {
	if v == "" {
		return ""
	}
	if mapped, ok := zenDeviceCategories[v]; ok {
		return mapped
	}
	return zenOther
}
