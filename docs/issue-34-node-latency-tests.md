# Issue 34: controlled subscription node latency tests

## Security boundary

The UI can submit only a configured `subscription_id`, a node name already
shown by the runtime catalog, and a non-sensitive batch operation id. It cannot
submit a probe URL, timeout, provider path, Controller address, or Controller
secret.

Rust derives the selector and provider names from the enabled subscription,
requires its protected credential state to be configured, and reads the first
validated HTTPS probe target plus `request_timeout_ms` from the active private
and Guardian settings. The existing `ControllerClient` still accepts only a
loopback address and authenticates with a random secret. When the main core is
stopped, catalog and latency commands start or reuse the existing app-owned
subscription probe runtime on random loopback ports. Its selectors default to
`REJECT`, it never binds the product entry, and it does not change the Windows
system proxy.

## Runtime flow

```text
UI node id
  -> validate enabled configured subscription
  -> choose the managed-core Controller, or an isolated probe Controller
  -> read authenticated selector snapshot
  -> require requested member in that snapshot
  -> provider-member healthcheck (validated URL and timeout)
  -> read authenticated selector snapshot again
  -> accept latency only when the authoritative current member is unchanged
```

Single-node testing never selects the node first. Batch testing enumerates the
authoritative provider members in Rust, uses four concurrent healthchecks at
most, preserves successes when another member fails, and stops queued work
after cancellation. An in-flight request is allowed to finish its bounded
healthcheck and mandatory selection readback.

With the main core stopped, selection invariance applies to the isolated probe
selector. The UI deliberately hides that temporary selector member and keeps
real node selection disabled until the main core is running again.

## Result lifetime and error model

Latency results, timestamps, node names, and batch state live only in React
memory. They are not written to product configuration, SQLite, or ordinary
logs. A catalog refresh marks displayed latency stale instead of treating
Mihomo history as a new active test.

The UI distinguishes waiting, running, success, failure, stale, and cancelled.
Failures use sanitized codes for both managed and isolated runtime unavailable,
provider unavailable, node disappearance, timeout, Controller failure, and
cancellation. If the
post-test selection cannot be read or differs from the pre-test selection, the
latency is rejected rather than presented as trusted.

## Explicit non-effects

This feature does not perform bandwidth tests, choose or switch to a faster
node, control third-party clients, or change the Windows system proxy, TUN,
DNS, routing, or third-party ports.
