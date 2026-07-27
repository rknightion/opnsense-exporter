package logship

// AttrDeviceCategory and AttrInterface are the two SHAPE dimensions a Source may set
// on a Record, alongside AttrSubsystem and AttrAction. Like those, the OTLP sink
// HOISTS them off the record onto the OTLP resource, which is the only place Loki can
// promote an attribute to an index label from — `otlp_config` has no index_label
// action for log attributes, so an attribute left on the record can never be indexed
// whatever the tenant config says. See sink_otlp.go.
//
// They exist because every investigation actually starts from one of two questions —
// which kind of device, and which network segment — and before #473 neither was
// selectable: both were structured metadata, so a query for one interface still
// scanned every record the subsystem ever shipped.
//
// Namespaced (opnsense.*) for the same collision-safety reason as attrSource, and set
// via these constants rather than literals: the sink hoists exactly these keys, so a
// lane spelling one differently would silently leave it on the record, unpromotable.
//
// CLOSED SETS ONLY, and both are for a DIFFERENT reason — worth keeping straight,
// because the two guards are not interchangeable:
//
//   - AttrDeviceCategory arrives from a push receiver, so the value is whatever the
//     sender put on the wire. It MUST be clamped to a code-defined vocabulary before
//     it is set (see zenarmor.clampDeviceCategory). Unclamped it is a sender minting
//     label values.
//   - AttrInterface is resolved by the exporter itself, against its own snapshot of
//     the firewall's interface configuration. Its value space is therefore the box's
//     interface list, and a name the box does not have simply does not resolve — so
//     the wire cannot introduce a value here at all.
//
// This is the DESCRIPTION space (LAN, IOT, MGMT — what the dashboard's $interface
// selects on), never the kernel device space (igb0, ixl0). The two are disjoint; see
// #98. A lane setting a kernel device name here would produce a label that silently
// matches nothing.
//
// Whether they ARE promoted is the tenant's choice and costs the exporter nothing:
// an unpromoted resource attribute lands in structured metadata. Each lane's own
// verbatim keys (`device.category`, `interface.name`) stay on the record untouched,
// so queries written against those keep working either way.
//
// Adding a THIRD shape dimension means re-checking maxLogResources against
// observedResourceCombos — the key count is a product, not a sum.
const (
	AttrDeviceCategory = "opnsense.device_category"
	AttrInterface      = "opnsense.interface"
)
