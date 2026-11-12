# Resource mode

One auth method, secrets engine, database plugin or storage backend between two versions.
- With `--current`, no cluster is needed.
- With `--report`, the version and edition come from the user's vault-tools audit report.

Never assume how the resource is configured. The capture, scope, applicability and severity rules are in SKILL.md step 4.

## 1. Identify the resource

Changes to a resource are filed under more than one name. Search all of them:

| Resource | Identifiers |
|---|---|
| LDAP auth | `auth/ldap` |
| LDAP secrets | `secrets/ldap`, `secrets/openldap`, static roles, Rotation Manager |
| PostgreSQL | the PostgreSQL plugin, `secrets/database`, database static roles |
| Raft | `storage/raft`, integrated storage, autopilot, snapshots |
| Others | the component name, plus its plugin name |

Work out how the resource ships:
- **Built-in plugin**: the plugin version moves with the Vault release.
- **External plugin**: the plugin version doesn't move with the Vault release. Check its SDK and runtime compatibility instead.

If you don't know which it is, assume built-in and say so.

## 2. Fetch: narrow on purpose

For each line in "Docs to read", fetch the important-changes page with a prompt that:
- names the identifiers from section 1 and the core areas below, and asks for the capture fields of those entries only
- asks for the **titles only** of the other breaking changes, as one line, so the report can point to them without assessing them

Core areas that act on the resource indirectly:

| Resource type | Core areas |
|---|---|
| Auth methods | token handling, identity and entity aliases, login flow, policy evaluation |
| Secrets engines | mounts, leases, rotation, plugin system |
| Database plugins | database secrets engine, static role rotation, plugin runtime |
| Storage backends | integrated storage, autopilot, snapshots, seal, replication |

Include an indirect change only when you can say how it affects the resource.

## 3. Use the script's API diff and plugin checks

The summary already covers what the API docs and plugin releases would tell you, so don't fetch those pages yourself:
- **"API changes"** compares the resource's API docs at the source line with the target line. It lists endpoints added or removed, parameters added or removed (ENT-marked), type and default changes, and newly deprecated parameters. Cite the source URL it prints. Treat a parameter that went from `<required>` to a default as a behaviour change worth a row. Report each API change as a finding only when it needs action or changes behaviour. Otherwise it's an improvement.
- **The 2.x docs cover every 2.x minor**, so an addition may postdate a 2.0 target. Check it against **"newer than the target's bundled"** under the plugin changelog: a feature listed there isn't in the target, even though the docs describe it.

Fetch a docs or API page only to explain something the diff can't, such as how a migration behaves or what a new parameter does. Ask only about that one endpoint or parameter. Fetch a plugin's GitHub releases page only when the summary says its changelog is unavailable and a plugin version could matter.

Mention compatibility with external systems only when a docs page states it.

## 4. Extra fields

- **Scope**: direct (the resource or its plugin) or indirect (core).
- **To verify**: for each Potential finding, the configuration detail that would settle it.

## 5. Check before writing

- Every identifier in section 1 was searched.
- Plugin versions are labelled estimated.
- If nothing changed, list what was searched. "No documented changes" isn't the same as "no impact".
- "Not covered" says the rest of the cluster wasn't assessed, and points to the other breaking-change titles collected in section 2.
