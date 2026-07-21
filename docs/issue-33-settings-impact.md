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

`system_proxy`, `tun`, and `service` are not ordinary settings fields. Unknown
draft fields are rejected during deserialization, while the known `entry` field
is rejected during preview and apply. Helper-owned and externally owned cores
also continue to reject private-routing changes that the desktop cannot prove
it can apply.

The primary UI action performs preview validation itself. Validation errors
focus an accessible summary; `live_apply` proceeds with the one-shot ticket;
and a running managed core plus `managed_core_reload` pauses for one explicit
confirmation. Editing the draft invalidates that confirmation and fingerprint.
