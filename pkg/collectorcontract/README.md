# Collector contract

Schema version stays `2.0`. Package pin `2.1.1` is what agents record. It is not the wire schema string.

`2.1.0` added an optional `opa_bundle.body` / `controls.body` string, filled only when the sync query is `include_policy=inline` and the two bodies together are at most 64 KiB. `include_policy` is a query parameter, not a `SyncRequest` field.

`2.1.1` adds three optional fields on `desired`:

| Field | Meaning |
|---|---|
| `mode` | `observe`, `enforce`, or `revoked`. Signed inside the manifest. |
| `revoked` | `true` when the publication is a revoke. The bundle is a deny-all tombstone (`default allow := false`, `data.json` `{"revoked":true}`), not the previous policy. `publications.mode` stays `observe` because that column only allows `observe` or `enforce`. |
| `quarantine` | Unsigned. `true` when an accepted workload link is quarantined at sync time. It does not rewrite `signed_manifest`. |

One collector receives one `desired`. That object is the highest visible delivery revision across every policy targeting the collector. An older policy for the same collector is not served. Publish does not reject that overlap.

`.signatures.json` inside the bundle is OPA's format: exactly one compact JWS. Overlap dual-sign lives on the detached manifest, because stock OPA rejects more than one bundle JWT.
