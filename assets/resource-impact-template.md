# Vault Upgrade Impact: {resource} ({source} → {target})

**Mode:** Resource Impact · **Resource:** {name} ({type}) · **Versions:** {source_resolved} → {target_resolved} {assumptions} · **Edition:** {edition} · **Plugin:** {Built-in (assumed) | External}, {from} → {to} (estimated)

**Overall risk:** {Critical | High | Medium | Low}. {2–3 sentences on what matters most.}

## Findings

One row per finding: breaking changes, new behaviour, deprecations, security fixes and active known issues, ordered by severity.

| Severity | Finding | Kind | Scope | Version | Edition | Applicability | Action | Source |
|---|---|---|---|---|---|---|---|---|
| {High} | {what changed} | {Breaking / Behaviour / Deprecation / CVE / Known issue (fixed in X or Open)} | {Direct / Indirect} | {version} | {All / ENT} | {Confirmed / Potential: applies if ...} | {action or workaround} | [{page}]({URL}) |

**Resolved by upgrading:** {known issues in the source that the target fixes}

## Improvements

- {improvement} ({version})

## Actions

- **Required (for an operator to run):** {list}
- **Optional:** {list}
- **Recommended target patch:** {version and reason, or "Target as requested"}

## To Verify

| Finding | Configuration detail that settles it |
|---|---|
| {finding} | {detail} |

## Not covered

- **Searched:** {identifiers} · **Sources:** {list}
- **Gaps:** {list}, plus: the rest of the cluster wasn't assessed (other breaking changes in the span: {titles}); run report mode with an audit report for that.

## What this means

{Two to four plain-language sentences for someone who isn't a Vault specialist: what changes, what could go wrong if the required actions are skipped, and the next step.}

---

Files: {summary .md}, {JSON}, {this report}. Read-only: nothing in Vault was contacted or changed.
