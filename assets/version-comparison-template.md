# Vault Upgrade Analysis: {source} → {target}

**Mode:** Version Comparison · **Versions:** {source_resolved} → {target_resolved} {assumptions} · **Edition:** {edition} · **Lines reviewed:** {e.g., 1.16, 1.17, 1.18}

**Overall risk:** {Critical | High | Medium | Low}. {2–3 sentences on the most significant findings.}

## Upgrade Path

{Prerequisites, intermediate versions and order, quoted from the upgrade docs. Omit if none found.}

## Findings

One row per finding, ordered by severity.

| Severity | Finding | Kind | Component | Version | Edition | Applicability | Action | Source |
|---|---|---|---|---|---|---|---|---|
| {High} | {what changed} | {Breaking / Behaviour / Deprecation / CVE (source affected? Y/N) / Known issue (fixed in X or Open) / Regression} | {core / auth/ldap / ...} | {1.17.0} | {All / ENT} | {Confirmed / Potential: applies if ...} | {action or workaround} | [{page}]({URL}) |

**Resolved by upgrading:** {known issues in the source that the target fixes}

## Improvements

- {improvement} ({version})

## Recommendation

- **Required:** {list}
- **Optional:** {list}
- **Recommended target patch:** {version and reason, or "Target as requested"}

## Not covered

- **Sources:** {list} · **Assumptions:** {list}
- **Gaps:** {e.g., Enterprise repo not read, plugin changelogs not checked in comparison mode, pages not fetched}

## What this means

{Two to four plain-language sentences for someone who isn't a Vault specialist: what changes, what could go wrong if the required actions are skipped, and the next step.}

---

Files: {summary .md}, {JSON}, {this report}. Read-only: nothing in Vault was contacted or changed.
