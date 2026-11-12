# Report mode

Everything a cluster runs, taken from the vault-tools audit report the user gave you. The report is your evidence; never contact the cluster for more, and never read the JSON or CSV files it lists. The capture, scope, applicability and severity rules are in SKILL.md step 4.

## 1. Build the inventory

The summary's "Inventory (from the audit report)" section lists:
- auth methods and secrets engines, with mount counts (per-namespace built-ins such as `ns_token` are folded into their type)
- namespaces
- Raft and replication
- audit device types and Sentinel counts
- coverage, from the report's "Access gaps"

Also record what the report **doesn't** show, because those gaps produce the Unknown findings:
- **Plugin versions**: plugin changelogs start from the version bundled with the current release ("estimated"), and whether a plugin is built-in or external isn't recorded.
- **Database plugins**: `database/<plugin>` matches whenever the database engine is mounted. Say "if you use the <plugin> plugin".
- **Storage backend**: storage entries are Unknown unless the report has an integrated storage (raft) section.
- **Deployment platform**: VM, container or Kubernetes.
- **Per-mount configuration**.
- **Access gaps**: if coverage is incomplete, a `not_in_use` breaking change could still apply.

You may read the report itself for a detail the summary doesn't carry, such as the replication peers, the autopilot configuration or a non-default audit option. Quote only what a finding needs.

## 2. Fetch

The order follows [sources.md](sources.md). Ask each fetch for the capture fields only, and name the in-use types in the prompt.

1. **Change tracker**: one fetch for every line from 1.16 on. Ask for the breaking changes, new behaviour and known issues in the span.
2. **Important changes** (1.16+) or **upgrade guides** (1.15 and older), for each line in "Docs to read".
3. **Deprecation notices** (within the span) and the target's **release notes** (the deprecation and EOL table, plus the "Enterprise" label for any finding whose edition the changelog and docs disagree on, or don't give).
4. **The LTS tracker**.
5. **For replicated or HA clusters**: the replicated-deployment and HA upgrade pages, for upgrade order. Quote their order; don't invent one.
6. **For each in-use type with a breaking change or deprecation**: the narrow fetches in [resource-impact.md](resource-impact.md) section 2.

## 3. Correlate each finding with the cluster

1. Find the affected component in the inventory. Treat each mount type on its own: the report gives counts per type, not per-mount config.
2. Classify each finding:
   - **Confirmed**: the report shows it applies.
   - **Potential**: the component exists, but the change depends on unrecorded config.
   - **Not affected**: the type isn't in use, and coverage is complete.
   - **Unknown**: the report lacks the field.
3. For each Potential or Unknown finding, say what would resolve it.

A mount being present isn't proof that every change to its type applies.

## 4. Group and check

Group findings by area:
- core
- auth methods
- secrets engines
- plugins
- storage and seal
- topology and procedure
- client-side
- Enterprise features

Within each group, put Confirmed findings first, then sort by severity.

Before writing, check:
- Every inventory item was searched. Items with no relevant changes go under "Unaffected", as one line.
- Report age, missing fields and access gaps are under "Not covered".
