# Issue #33 settings impact contract

Ordinary settings keep the existing fingerprinted preview ticket and atomic
settings journal. The preview now classifies every changed field before the UI
chooses whether to apply immediately or ask for a managed-core reload
confirmation.

| Draft field | Impact | Runtime action |
| --- | --- | --- |
| `entry` | `dedicated_transaction` | Reject ordinary settings and direct the user to the entry-switch transaction. |
| `route_mode`, `manual_outlet` | `live_apply` | Persist atomically, then run the authenticated Controller routing cycle. |
| `cooldown_seconds`, `minimum_improvement_ms` | `live_apply` | Update the routing policy used by the authenticated Controller cycle. |
| Guardian interval, timeouts and thresholds | `live_apply` | Reload the desktop Guardian schedule without restarting Mihomo. |
| `retention_days` | `live_apply` | Update retention and remove expired rows inside the settings transaction. |
| `probe_targets` | `managed_core_reload` | Regenerate Mihomo provider health-check configuration and use the Issue #32 reload path. |
| Outlet definitions, order, enabled state and provider period | `managed_core_reload` | Regenerate Mihomo YAML and use the Issue #32 reload path. |
| Credential set/delete intent | `managed_core_reload` | Stage the protected secret and use the Issue #32 reload path without exposing its value. |

When a managed core is running, a `live_apply` change that affects the
authenticated Controller stays in the journal's runtime-validation-pending
phase until both the Controller cycle and final database commit succeed. Before
the transaction starts, the desktop reads the authoritative current members of
both `VPN-HUB-MASTER` and `VPN-HUB-UDP` in one authenticated Controller
snapshot. A rejected cycle, or a finalization failure before the durable commit
decision, enters the same compensation path: restore the previous private and
Guardian files, the exact in-memory routing snapshot, and both Controller
selections with authoritative readback; then clean the journal and require a
fresh preview ticket before retrying.

`CommitDecided` is the one-way durability boundary. It is atomically persisted
before protected-credential deletion, retention/history cleanup, or any other
irreversible side effect. A failure after that decision leaves the journal for
idempotent roll-forward on the next attempt or restart; it never reports a
rollback. This includes a database commit followed by failure to persist the
`Finalized` journal phase.

If the old selections cannot be confirmed, both selectors are set to `REJECT`
and read back, the in-memory current route is cleared, and a separate private
`runtime/settings-terminal.json` gate is atomically persisted with an adjacent
backup. The `Pending` intent is durable before rollback evidence is cleaned or
any selector restoration is attempted. It is removed only after both old
selectors are restored and authoritatively read back. Main, backup, and orphan
`.new` gate artifacts are all treated as active after a crash, so no boundary
can restart without either the settings journal or the terminal gate.

The gate survives transaction-journal cleanup and restart. While it is active,
config reloads, scheduled probes, network-triggered probes, and new settings
applies cannot enter Guardian routing; they only reassert and read back
`REJECT` for both selectors. The Settings UI exposes one explicit recovery
action. If no owned core survived the restart, that action uses a dedicated
startup path: start a desktop-owned core in its initial double-`REJECT` state,
prove exact PID and Controller ownership, authenticate and read back both
selectors, durably remove the gate, and only then publish the core to automatic
routing. It never borrows a Helper-owned or external Controller. Controller
unavailability, failed authentication, failed ownership, failed readback, or a
damaged gate remains fail closed.

Credential deletion follows the same one-way boundary. During
`RuntimeValidationPending`, the formal protected credential remains present;
runtime YAML generation uses a transaction-scoped candidate view that omits
credentials marked for deletion. The formal credential is deleted only after
`CommitDecided` is durable, and restart recovery repeats that deletion
idempotently while rolling forward.

`system_proxy`, `tun`, and `service` are not ordinary settings fields. Unknown
draft fields are rejected during deserialization, while the known `entry` field
is rejected during preview and apply. Helper-owned and externally owned cores
also continue to reject private-routing changes that the desktop cannot prove
it can apply.

The primary UI action performs preview validation itself. Validation errors
focus an accessible summary; `live_apply` proceeds with the one-shot ticket;
and a running managed core plus `managed_core_reload` pauses for one explicit
confirmation. Editing the draft invalidates that confirmation and fingerprint.
Validation fields are attributed to their exact editable control, including
connection timeout, recovery threshold, and per-outlet label, host, port, and
provider period; generic routing failures fall back to the outlet section
instead of incorrectly marking the route-mode selector.
