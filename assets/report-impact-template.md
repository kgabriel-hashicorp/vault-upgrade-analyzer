# Vault Upgrade Impact: {cluster name} ({source} → {target})

**Mode:** Report Impact · **Versions:** {source_resolved} (from report) → {target_resolved} · **Edition:** {from report} · **Audit report:** {file}, generated {date} {flag if over 24h} · **Lines reviewed:** {list}

**Overall risk:** {Critical | High | Medium | Low}. {2–3 sentences on what matters most.} Findings: {n} Confirmed, {n} Potential, {n} Unknown.

## Cluster Inventory

| Type | Mounts | Namespaces |
|---|---|---|
| {secrets: database} | {2} | {1} |

**Storage / seal:** {e.g., Raft, 5 nodes, autopilot} · **Topology:** {HA, PR/DR} · **Platform:** {or "Not recorded"}

## Upgrade Path and Order

{Prerequisites, intermediate versions, and the upgrade order for this topology quoted from the replicated-deployment and HA docs. Omit if nothing applies.}

## Findings

Group by area (core; auth methods; secrets engines; plugins; storage and seal; client-side; Enterprise). One row per finding, Confirmed first, then by severity.

### {Area}

| Severity | Finding | Kind | Affects | Version | Edition | Applicability | Action | Source |
|---|---|---|---|---|---|---|---|---|
| {Critical} | {what changed} | {Breaking / Behaviour / Deprecation / CVE / Known issue (fixed in X or Open) / Regression} | {mount type or Core} | {version} | {All / ENT} | {Confirmed / Potential: ... / Unknown: ...} | {action or workaround} | [{page}]({URL}) |

**Resolved by upgrading:** {known issues relevant to this cluster that the target fixes}

## Actions

- **Before upgrade:** {list, for an operator to run}
- **After upgrade:** {list, including validation checks tied to specific findings}
- **Optional:** {list}
- **Recommended target patch:** {version and reason, or "Target as requested"}

## To Verify

| Finding | What to check (a command only if a fetched docs page gives it) |
|---|---|
| {finding} | {check} |

**Unaffected:** {inventory items with no relevant changes, one line}

## Not covered

- **Sources:** {list}
- **Audit report:** {age; missing fields; access gaps}
- **Gaps:** {list}

## What this means

{Two to four plain-language sentences for someone who isn't a Vault specialist: what changes, what could go wrong if the required actions are skipped, and the next step.}

---

Files: {summary .md}, {JSON}, {this report}. Read-only: nothing in Vault was contacted or changed.
