# Changelog

## 0.1.0 (unreleased)

First published version.

- Three modes: version comparison, one resource (auth method, secrets engine, database plugin, storage backend), and a whole cluster from a vault-tools audit report.
- `scripts/version_check.py` parses the Vault changelog (and the private vault-enterprise changelog when the user's `gh` login can read it), drops backports the current version already shipped, tags entries by relevance, reads plugin changelogs and diffs the resource's API docs between release lines.
- API docs diff finds pages kept in a folder: KV maps to `kv/kv-v2.mdx`, and other engines fall back to `<type>/index.mdx` on a 404.
- The latest-line release notes are a source for settling an entry's edition.
- Packaged as a Claude Code plugin with its own marketplace at kgabriel-hashicorp/vault-upgrade-analyzer, licensed MPL-2.0.
- Works in any Agent Skills-compatible agent: the script path no longer depends on `${CLAUDE_SKILL_DIR}`.
