# Sources

Where every product fact in this skill comes from. Version-specific facts (breaking changes, known issues, CVEs) are never stored here. The skill fetches them at runtime from the URL patterns below.

## Source priority

When sources conflict, prefer the earlier one and note the conflict in the report. **Edition** is the exception: when the changelog has no `(enterprise)` tag and the sources disagree on edition, the release notes' "Enterprise" label decides it.

1. Change tracker (1.16 onwards)
2. Important changes (1.16 onwards) or upgrade guides (1.15 and earlier)
3. Deprecation notices
4. Release notes
5. Vault changelog (read by the script)
6. Plugin changelogs (read by the script)

## Primary (developer.hashicorp.com)

| Page | URL | Fetched | Used for |
|---|---|---|---|
| Change tracker | https://developer.hashicorp.com/vault/docs/updates/change-tracker | 2026-10-26 | First finding list. One section per line from 1.16.x to 2.x, with breaking changes and new behaviour (introduced version, edition All, Enterprise or CE) and known issues (found, fixed, workaround Yes, No, Partial or Upgrade). Nothing before 1.16. |
| Important changes, 2.x | https://developer.hashicorp.com/vault/docs/v2.x/updates/important-changes | 2026-10-26 | One page covers every 2.x minor. Breaking changes, new behaviour and known issues, each with affected version, edition, status, and a recommendation or workaround. |
| Important changes, 1.21.x | https://developer.hashicorp.com/vault/docs/v1.21.x/updates/important-changes | 2026-10-26 | The per-minor page pattern for 1.16 to 1.21 |
| Release notes, 1.21.x | https://developer.hashicorp.com/vault/docs/v1.21.x/updates/release-notes | 2026-10-26 | The per-minor pattern for features and the deprecation and EOL table |
| Release notes, 2.x | https://developer.hashicorp.com/vault/docs/v2.x/updates/release-notes | 2026-10-26 | Features and deprecations for 2.x |
| Release notes, latest | https://developer.hashicorp.com/vault/docs/updates/release-notes | 2026-11-05 | The latest line's release notes (2.x on this date: 2.0.0 to 2.2.1). One section per patch, newest first, with New features, Bug fixes and security patches, and Improvements and behavior changes. Enterprise-only entries carry a plain-text "Enterprise" label on the line before the entry; unlabelled entries are in both editions. Use it to settle an entry's edition when the changelog has no `(enterprise)` tag, because the private vault-enterprise repo is often unreadable. Cite the versioned URL (`v2.x`) in reports. |
| Upgrade guide, 1.15.x | https://developer.hashicorp.com/vault/docs/v1.15.x/upgrading/upgrade-to-1.15.x | 2026-10-26 | Lines 1.15 and older have only upgrade guides, each covering the previous minor |
| LTS tracker | https://developer.hashicorp.com/vault/docs/updates/lts-tracker | 2026-10-26 | Which line is the current LTS. The page lists LTS under the Enterprise edition; it doesn't say Community is excluded, so don't claim it. |
| Deprecation notices | https://developer.hashicorp.com/vault/docs/updates/deprecation | 2026-10-26 | Deprecated, pending removal and removed features, with announced date, end of support and removal |
| Upgrade Vault | https://developer.hashicorp.com/vault/docs/upgrade | 2026-10-26 | Back up data and config and take a snapshot first. Review the change tracker, release notes and deprecations. Test the upgrade on a restored snapshot. |
| Replicated deployments | https://developer.hashicorp.com/vault/docs/upgrade/replicated-deployment | 2026-10-26 | Upgrade replication secondaries first and the primary last. Upstream clusters stay on older versions than downstream. With Autopilot (1.11+, Integrated Storage), let Autopilot run the HA upgrade. |
| HA upgrade | https://developer.hashicorp.com/vault/docs/upgrade/vault-ha-upgrade | 2026-10-26 | Order within an HA cluster |
| Rollback | https://developer.hashicorp.com/vault/docs/upgrade/rollback | 2026-10-26 | Rollback planning, for the checklist |
| Plugin upgrades | https://developer.hashicorp.com/vault/docs/plugins/upgrade | 2026-10-26 | External plugin upgrade procedure |
| Agent and Proxy upgrades | https://developer.hashicorp.com/vault/docs/agent-and-proxy/upgrade | 2026-10-26 | Client-side findings |

## Secondary (github.com/hashicorp)

| Page | URL | Fetched | Used for |
|---|---|---|---|
| Vault changelog | https://github.com/hashicorp/vault/blob/main/CHANGELOG.md | 2026-10-26 | Per-release entries, including `SECURITY:` entries with CVE IDs. Read by the script. |
| Vault go.mod | https://github.com/hashicorp/vault/blob/main/go.mod | 2026-10-26 | The plugin version bundled at a release tag, when the changelog doesn't give it |
| Example plugin changelog | https://github.com/hashicorp/vault-plugin-secrets-openldap/blob/main/CHANGELOG.md | 2026-10-26 | The plugin changelog format the script reads |

## Runtime URL patterns

Fetched by the skill or the script when it runs, for facts that change between versions:
- `/vault/docs/v2.x/updates/important-changes` and `/vault/docs/v2.x/updates/release-notes`: one page per **major** 2.x line. Per-minor 2.x paths (`v2.1.x`) return 404.
- `/vault/docs/v1.N.x/updates/important-changes` and `/vault/docs/v1.N.x/updates/release-notes`, for 1.16 to 1.21
- `/vault/docs/v1.N.x/upgrading/upgrade-to-1.N.x`, for 1.15 and older. Read every guide in the range.
- Unversioned paths (`/vault/docs/updates/important-changes`) always point to the latest line. Cite versioned URLs.
- The change tracker's links sometimes point to another version's page. Check the destination's version before citing it.
- `github.com/hashicorp/vault/blob/main/CHANGELOG-v1.10-v1.15.md` and `CHANGELOG-pre-v1.10.md`: older changelog entries. The script downloads only the files the span needs.
- `github.com/hashicorp/vault/blob/v<X.Y.Z>/go.mod`: the plugin version bundled at a release tag
- `raw.githubusercontent.com/hashicorp/web-unified-docs/main/content/vault/<v1.N.x | v2.x>/content/api-docs/<secret|auth>/<type>.mdx`: the markdown behind the versioned API docs, plus `content/partials/` for `@include`d parameter lists. The script diffs the source and target lines in resource mode.
- `github.com/hashicorp/<plugin-repo>/releases`: plugin versions missing from the plugin's `main` CHANGELOG
- `github.com/hashicorp/vault-enterprise`: private. Read through `gh api` only if the user's existing login can read it.

## Changelog format (what the script relies on)

- Release headings are `## X.Y.Z` (Enterprise-only patches: `## X.Y.Z Enterprise`), followed by a date line. Sections are `BREAKING CHANGES:`, `DEPRECATIONS:`, `SECURITY:`, `CHANGES:`, `FEATURES:`, `IMPROVEMENTS:` and `BUG FIXES:`. Entries are `* component: text`, with components like `auth/<type>`, `secrets/<type>`, `database/<plugin>`, `storage/raft`, `core` and `ui`. Enterprise-only entries are tagged `component (enterprise):`.
- Patches on older lines keep shipping after newer minors. The script drops releases dated after the target, because their fixes may not be in the target yet, and lists them as "Excluded".
- Backported fixes repeat in later releases. The script drops entries the current version's line already shipped and counts them.
- The `changelog/` directory holds unreleased entries. Never cite them as shipped.

## Plugin changelogs

- Many auth methods, secrets engines and database plugins ship as separate plugins, for example `vault-plugin-secrets-openldap` (the LDAP secrets engine), `vault-plugin-auth-jwt` (JWT/OIDC) and `vault-plugin-database-snowflake`. Vault's changelog records only "Update plugin to vX.Y.Z".
- The script estimates the start version from the last "Update plugin to" entry at or before the current version ("estimated"). Neither input records the running plugin version. Plugin types built into Vault's own binary have no plugin changelog.
- A separate repo doesn't mean the plugin is deployed externally. An external plugin's version doesn't change with a Vault upgrade; check its SDK and runtime compatibility instead.
- Housekeeping lines (dependency bumps, CI, copyright) are dropped unless they affect compatibility or security.

## CVEs

The Vault changelog's `SECURITY:` entries carry CVE IDs and the release that fixed them. The script collapses dependency-bump advisories into a count. No developer.hashicorp.com page lists CVEs per release, so report a CVE only from the changelog or an important-changes page, and say which.

## Audit report

Report mode reads a vault-tools namespace audit report (markdown) that the user provides. The script takes the header's `Vault version`, `Cluster` and `Generated` fields, the Summary, Cluster health, Integrated storage (raft), Audit devices and Access gaps sections, and the Auth methods and Secrets engines type tables. Never read the JSON and CSV files the report lists under "Output files".

## Script errors

What to tell the user when the script exits 1, by the stderr message:

| stderr on exit 1 | Tell the user |
|---|---|
| `report ... not found` | Check the path with the user. |
| `cannot find the Vault version` | The file isn't a vault-tools audit report, or its header lacks `Vault version`. Ask for the current version and run comparison or resource mode. |
| `has no mount inventory` | The report came from a sealed, uninitialised or DR-secondary node. Ask for a report from the primary or an unsealed active node, or use resource mode. |
| `unknown resource` | Map the user's words to a resource form (SKILL.md step 1), or ask. |
| `is not newer than the current` | They're already at or past that version. Say so. |
| `is not in the Vault changelog` | The version doesn't exist yet. Give the latest version the message names. |
| `cannot download ... CHANGELOG.md` | GitHub isn't reachable. The user can download the changelog and pass `--changelog <file>`. Plugin changelogs are then skipped; list that under "Not covered". |
