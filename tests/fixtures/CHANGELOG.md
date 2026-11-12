## Previous versions
- [v1.10.0 - v1.15.16](CHANGELOG-v1.10-v1.15.md)

## 2.1.0
### September 1, 2026

BREAKING CHANGES:

* secrets/pki: sign-verbatim now rejects CSRs with URI SANs.

SECURITY:

* Upgrade `example/lib` to v1.2.3 to resolve CVE-2026-0001
* auth/userpass: timing side channel in userpass login (CVE-2026-0002)

CHANGES:

* secrets/openldap: Update plugin to [v0.18.1](https://github.com/hashicorp/vault-plugin-secrets-openldap/releases/tag/v0.18.1)
* core: Bump Go version to 1.26.7
* core: Fix shared thing in the router [[GH-1](https://github.com/hashicorp/vault/pull/1)]
* secrets/ldap (enterprise): Static roles move to the Rotation Manager.

BUG FIXES:

* ldap auth (enterprise): fix group lookup for LDAP logins.
* ui: Fix LDAP check-out capabilities check.
* secrets/kv: fix a KV v2 listing bug.

## 1.19.8
### October 1, 2026

BUG FIXES:

* core: late fix that 2.1.0 does not have yet

## 1.19.7 Enterprise
### August 1, 2026

BUG FIXES:

* secrets/transit: Enterprise-only transit fix.

## 1.19.6
### July 1, 2026

BUG FIXES:

* core: Fix shared thing in the router [[GH-2](https://github.com/hashicorp/vault/pull/2)]
* secrets/pki: fix CRL rebuild.

## 1.19.5
### June 1, 2026

CHANGES:

* secrets/openldap: Update plugin to [v0.15.4](https://github.com/hashicorp/vault-plugin-secrets-openldap/releases/tag/v0.15.4)

BUG FIXES:

* core: Fix shared thing in the router [[GH-3](https://github.com/hashicorp/vault/pull/3)]

## 1.19.0
## March 1, 2026

FEATURES:

* core: the 1.19 line starts here.
