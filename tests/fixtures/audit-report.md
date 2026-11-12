# Vault Namespace Audit — vault-test

| Field | Value |
| --- | --- |
| Cluster | vault-test |
| Generated | 2026-03-20 10:00:00 UTC |
| Tool version | vault-tools 3.1.0 |
| Vault version | 1.19.5 (Community) |

## Summary

| Metric | Value |
| --- | --- |
| Namespaces | 1 |
| Permission denied (skipped) | 0 |
| Sentinel EGP policies | 0 |
| Sentinel RGP policies | 0 |

## Cluster health

| Field | Value |
| --- | --- |
| Sealed | no |
| DR replication mode | disabled |
| Performance replication mode | disabled |

### Integrated storage (raft)

| Node | Leader | Voter | Autopilot status | Healthy | Last contact |
| --- | --- | --- | --- | --- | --- |
| vault-0 | yes | yes | leader | yes | 0s |

### Audit devices

| Path | Type | Sink | Local | Non-default options |
| --- | --- | --- | --- | --- |
| `file/` | file | file | no | none |

## Access gaps

None — the audit covered the full tree reachable from `/`.

## Type distribution

### Auth methods

| Auth method type | Mounts | Namespaces |
| --- | --- | --- |
| userpass | 1 | 1 |
| token | 1 | 1 |

### Secrets engines

| Secrets engine type | Mounts | Namespaces |
| --- | --- | --- |
| pki | 2 | 1 |
| ns_system | 3 | 3 |
| system | 1 | 1 |
