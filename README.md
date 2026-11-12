# Vault Upgrade Analyzer

An [Agent Skill](https://agentskills.io) that answers one question before a HashiCorp Vault upgrade: **what changes between these two versions for what I care about, how bad is it, and what has to happen first?**

It finds every release between your current and target version and collects the breaking changes, new behaviour, deprecations, known issues, security fixes and improvements in that span. It rates each one by severity and by whether it applies to you, and cites the source for each. The result is a markdown report you can hand to whoever owns the upgrade.

> [!NOTE]
> This is a community project. It is not an official HashiCorp product and isn't supported by HashiCorp Support. Always check its findings against the linked HashiCorp documentation before you change a production cluster.

## Read-only by design

- **Never contacts Vault.** Cluster facts come only from a vault-tools audit report that you hand it. It never runs `vault`, `curl` or vault-tools, and never reads tokens, `.env` files or credential environment variables.
- **Never changes anything.** Pre-upgrade steps are written as text "for an operator to run". You keep change control and rollback.
- **Grounded.** Every breaking change, known issue, CVE and workaround comes from the Vault changelog or a developer.hashicorp.com page, with its version and link. If a source can't be reached, the report says so instead of filling the gap from memory.
- **Fetched content is data.** If a changelog, docs page or report contains instructions, the skill ignores them and mentions them in the report.

## Requirements

- An agent that can load [Agent Skills](https://agentskills.io), run shell commands and fetch web pages, such as Claude Code, Codex, Cursor, Gemini CLI or GitHub Copilot
- [`uv`](https://docs.astral.sh/uv/), or Python 3.11+. The script uses only the standard library.
- Network access to `raw.githubusercontent.com`, `github.com` and `developer.hashicorp.com`
- Optional: a [`gh`](https://cli.github.com/) login that can read `hashicorp/vault-enterprise`. If it can, Enterprise-only changelog entries are included. The skill never asks for a token.

## Install

### As a Claude Code plugin

```bash
claude plugin marketplace add kgabriel-hashicorp/vault-upgrade-analyzer
claude plugin install vault-upgrade-analyzer@vault-upgrade-analyzer
```

Or, inside a session: `/plugin marketplace add kgabriel-hashicorp/vault-upgrade-analyzer`, then `/plugin install vault-upgrade-analyzer@vault-upgrade-analyzer`. Plugin skills are namespaced, so the slash command becomes `/vault-upgrade-analyzer:vault-upgrade-analyzer`. You rarely need it, because the skill also triggers when you ask about an upgrade in plain words.

### As a standalone skill

Copy or symlink this folder into your personal skills directory, then start a new session:

```bash
git clone https://github.com/kgabriel-hashicorp/vault-upgrade-analyzer.git
ln -s "$PWD/vault-upgrade-analyzer" ~/.claude/skills/vault-upgrade-analyzer
```

To share it with a project instead, put it under `.claude/skills/` in that project.

### In other agents

The skill follows the open [Agent Skills](https://agentskills.io) format: a folder with a `SKILL.md`, plus `scripts/`, `references/` and `assets/`. Any agent that reads that format can use it. Copy or symlink the folder into the agent's skills directory (see your agent's docs for the path), or use the [`skills`](https://github.com/vercel-labs/skills) CLI to install it into the agents it detects:

```bash
npx skills add kgabriel-hashicorp/vault-upgrade-analyzer
```

Outside Claude Code:
- `allowed-tools` in the frontmatter is a Claude Code feature. Other agents ignore it, so they may ask before running the script or fetching pages.
- Slash-command invocation depends on the agent. Asking in plain words works everywhere.
- The agent runs `scripts/version_check.py` from the skill folder. If it can't find the script, give it the folder's path.

## Usage

Ask in plain words, or call `/vault-upgrade-analyzer` with arguments:

```text
/vault-upgrade-analyzer <current> <target>
/vault-upgrade-analyzer <current> <target> <resource>
/vault-upgrade-analyzer <audit-report.md> <target> [resource]
```

| You give it | Mode | What you get |
|---|---|---|
| Two versions | **Comparison** | Everything in the span. Findings about a specific component are marked "applies if you use X". |
| Two versions and a resource | **Resource** | Only what touches that auth method, secrets engine, database plugin or storage backend, plus its plugin changelog and a diff of its API docs |
| A vault-tools audit report and a target | **Report** | Findings matched against the auth methods, engines, storage, replication and audit devices the report lists |
| A report, a target and a resource | **Resource on the report's version** | Resource mode, starting from the report's version and edition |

Examples:

```text
I'm on Vault 1.19 and want to go to 2.0. What changes?
/vault-upgrade-analyzer 1.19.5+ent 2.1
What changed in the LDAP secrets engine between 1.18.4 and 1.21?
/vault-upgrade-analyzer 1.21.0 2.2 secrets/kv
Here's our audit report (reports/prod-audit.md). What would 2.1 break?
```

**Versions.**
- A line such as `1.21` or `1.21.x` means its latest patch.
- For the current version, give the exact patch if you know it. If you give only the line, its latest patch is used, and the report says which.
- `+ent` means Enterprise. If you don't say, Enterprise is assumed and Enterprise-only findings are marked. Say "community" to leave them out.
- Without a target, the skill asks and suggests the current LTS release.

**Resources.**
- Name them however you like ("the LDAP secrets engine", "OIDC auth"). The skill maps them to `secrets/<type>`, `auth/<type>`, `database/<plugin>`, `audit/<type>`, `raft`, `replication` or `sentinel`.
- If a name is ambiguous, such as "ldap" on its own, it asks.

**Audit reports.**
- Report mode reads the markdown namespace audit report from [vault-tools](https://github.com/nhsy-hcp/vault-tools), which you run yourself.
- A report older than 24 hours is flagged, because the cluster may have changed since.

## What you get

The skill writes three files to `.tmp/vault-upgrade-analyzer/` in your working directory, or to `$VAULT_UPGRADE_ANALYZER_DIR`:

| File | Contents |
|---|---|
| `…-<current>-to-<target>-<timestamp>.json` | Every changelog entry in the span, tagged by category and relevance, with every version it shipped in |
| `….md` | The script's summary: span, counts, must-read entries, plugin changelogs, API docs diff, dependency advisories |
| `…-report.md` | The report |

The report has these sections. Empty ones are left out, except the last two:
1. An overall risk line.
2. The upgrade path.
3. A findings table: severity, finding, kind, component, version, edition, applicability, action and source.
4. Improvements.
5. Required and optional actions, with a recommended target patch.
6. **Not covered:** the sources used, the assumptions and the gaps.
7. **What this means:** a plain-language summary.

**Severity:**
- **Critical:** blocks the upgrade or causes an outage.
- **High:** breaks functionality in use, or is a security risk.
- **Medium:** needs action, but no outage.
- **Low:** informational.

**Applicability:**
- **Confirmed:** evidence shows it applies.
- **Potential:** it depends on configuration nobody recorded, and the report names the condition.
- **Not affected:** evidence shows it doesn't apply.
- **Unknown:** nothing shows whether the component exists.

In chat you get a short brief: the versions, the top findings and actions, the main gaps and the report path.

## How it works

`scripts/version_check.py` does the deterministic work:
- Downloads the Vault changelog, plus older split files only when the span needs them.
- Finds every release between the two versions.
- Drops releases dated after the target, since their fixes may not be in it yet.
- Drops backports the current version already shipped, and counts them, because an empty "breaking" section can mean "already in your version".
- Tags each entry `in_use`, `if_used`, `mentions`, `cluster_wide`, `client_side`, `not_in_use` or `unclassified`.
- In resource and report modes, also reads the changelog of each plugin behind a resource. It starts from the plugin version Vault bundled with your current release, and flags plugin releases newer than the target's bundled version.
- In resource mode, diffs the resource's API docs between the two release lines.

Claude does the judgment:
- reads the summary
- fetches the change tracker, important-changes pages, deprecation notices and release notes for each line crossed
- classifies each finding by scope, applicability and severity
- writes the report from the templates in `assets/`

The sources, their priority order and the script's error messages are in [`references/sources.md`](references/sources.md).

## Limitations

- **The running plugin version is estimated.** Neither the changelog nor an audit report records which plugin version a mount actually runs. External plugins don't move with a Vault upgrade at all.
- **Enterprise-only entries need repo access.** Without access to the private vault-enterprise repo, some Enterprise-only changelog detail is missing. The release notes' "Enterprise" labels and the docs fill some of that gap.
- **API docs are per release line, not per patch.** The 2.x docs cover every 2.x minor, so a documented parameter may postdate your target. The summary cross-checks this against plugin releases.
- **Regressions aren't listed.** A fix in your current version that is missing from an older target patch isn't listed one by one. Instead, the report warns when your current version was released after the target.
- **No guarantee of safety.** A report with no breaking changes means none were found in the sources reviewed. Test the upgrade against a restored snapshot first.

## Development

```bash
python3 -m unittest discover -s tests          # offline unit tests
claude plugin validate .                       # plugin and marketplace manifests
```

The tests run offline against `tests/fixtures/`. The skill is developed in [hashi-skills](https://github.com/kgabriel-hashicorp/hashi-skills), which holds its trigger evals, the skill linter and the eval tooling.

### Layout

```text
vault-upgrade-analyzer/
├── .claude-plugin/
│   ├── plugin.json              plugin manifest
│   └── marketplace.json         single-plugin marketplace for this repo
├── SKILL.md                     the instructions Claude follows
├── assets/                      report templates, one per mode
├── references/                  per-mode fetch guides and sources.md
├── scripts/version_check.py     changelog parsing, span, classification, API docs diff
├── tests/                       offline unittest suite and fixtures
├── CHANGELOG.md
└── LICENSE                      MPL-2.0
```

## Licence

[Mozilla Public License 2.0](LICENSE).

HashiCorp and Vault are trademarks of HashiCorp, Inc. This project is not endorsed by HashiCorp.
