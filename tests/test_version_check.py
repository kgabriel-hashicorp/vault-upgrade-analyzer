"""version_check.py tests against a small hand-written changelog (no network).

Run: python3 -m unittest discover -s vault/vault-upgrade-analyzer/tests
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

HERE = Path(__file__).parent
SCRIPT = HERE.parent / "scripts" / "version_check.py"
CHANGELOG = HERE / "fixtures" / "CHANGELOG.md"
REPORT = HERE / "fixtures" / "audit-report.md"
sys.path.insert(0, str(SCRIPT.parent))
import version_check as vc  # noqa: E402

RELEASES = vc.parse_changelog(CHANGELOG.read_text(), "fixture")
META = {"inputs": {}, "sources": {"changelog": [], "enterprise_repo": "n/a"}, "cluster_name": "t", "version_raw": "", "requested": "2.1"}


def cluster(auth=(), secrets=()) -> dict:
    return {
        "auth_types": {t: {"mounts": 1, "namespaces": 1} for t in auth}, "secrets_types": {t: {"mounts": 1, "namespaces": 1} for t in secrets},
        "namespaces": 1, "raft": True, "replication": {"active": False, "dr": "disabled", "performance": "disabled"},
        "audit_device_types": ["file"], "sentinel": {"egp": 0, "rgp": 0},
    }  # fmt: skip


def texts(doc: dict) -> list[str]:
    return [x["text"] for x in doc["impact"]]


class Parsing(unittest.TestCase):
    def test_releases_dates_and_editions(self) -> None:
        by = {r["version"]: r for r in RELEASES}
        self.assertEqual(set(by), {(2, 1, 0), (1, 19, 8), (1, 19, 7), (1, 19, 6), (1, 19, 5), (1, 19, 0)})
        self.assertTrue(by[(1, 19, 7)]["enterprise_only"])
        self.assertEqual(by[(1, 19, 0)]["date"], "2026-03-01")  # "## March 1, 2026" form

    def test_resolve_target(self) -> None:
        self.assertEqual(vc.resolve_target("2.1", RELEASES, enterprise=True), (2, 1, 0))
        self.assertEqual(vc.resolve_target("1.19.x", RELEASES, enterprise=False), (1, 19, 8))

    def test_build_suffix_on_current(self) -> None:
        self.assertEqual(vc.resolve_current("1.19.5+ent", RELEASES, enterprise=True), (1, 19, 5))

    def test_current_line_means_latest_patch(self) -> None:
        self.assertEqual(vc.resolve_current("v1.19", RELEASES, enterprise=True), (1, 19, 8))
        self.assertEqual(vc.resolve_current("1.19.x", RELEASES, enterprise=False), (1, 19, 8))
        self.assertEqual(vc.resolve_current("1.19.0", RELEASES, enterprise=True), (1, 19, 0))

    def test_docs_links(self) -> None:
        links = {d["line"]: d["important_changes"] for d in vc.docs_links([(1, 19), (2, 0), (2, 1)])}
        self.assertTrue(links["1.19.x"].endswith("/v1.19.x/updates/important-changes"))
        self.assertTrue(links["2.x"].endswith("/v2.x/updates/important-changes"))
        self.assertIn("lts", links)


class AuditReport(unittest.TestCase):
    def setUp(self) -> None:
        self.r = vc.parse_audit_report(REPORT)

    def test_version_and_edition(self) -> None:
        self.assertEqual((self.r["version"], self.r["enterprise"], self.r["cluster_name"]), ((1, 19, 5), False, "vault-test"))

    def test_inventory(self) -> None:
        p = self.r["profile"]
        self.assertEqual(set(p["auth_types"]), {"userpass", "token"})
        self.assertEqual(p["secrets_types"]["pki"], {"mounts": 2, "namespaces": 1})
        self.assertEqual(p["secrets_types"]["system"], {"mounts": 4, "namespaces": 4})  # ns_system folds into system
        self.assertTrue(p["raft"])
        self.assertFalse(p["replication"]["active"])
        self.assertEqual(p["audit_device_types"], ["file"])
        self.assertTrue(p["inventory_coverage_complete"])
        self.assertIsNone(p["database_plugins"])

    def test_not_a_report(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".md") as f:
            f.write("# Notes\n\nnothing here\n")
            f.flush()
            res = subprocess.run([sys.executable, str(SCRIPT), "--report", f.name, "--target", "2.1", "--changelog", str(CHANGELOG)], capture_output=True, text=True)
        self.assertEqual(res.returncode, 1)
        self.assertIn("cannot find the Vault version", res.stderr)


class ReportMode(unittest.TestCase):
    def setUp(self) -> None:
        self.doc = vc.build_document((1, 19, 5), (2, 1, 0), False, RELEASES, cluster(auth=["userpass"], secrets=["pki"]), META)

    def test_span_excludes_releases_after_target_and_enterprise_only(self) -> None:
        self.assertEqual(self.doc["span"]["releases"], ["1.19.6", "2.1.0"])
        self.assertEqual(self.doc["span"]["excluded_released_after_target"], ["1.19.8"])

    def test_backports_already_shipped_are_dropped(self) -> None:
        # The router fix shipped in 1.19.5 and was repeated (different PR refs) in 1.19.6 and 2.1.0.
        self.assertEqual(self.doc["span"]["already_shipped_dropped"], 2)
        self.assertFalse(any("shared thing" in t for t in texts(self.doc)))

    def test_classification(self) -> None:
        rel = {x["text"][:30]: x["relevance"] for x in self.doc["impact"]}
        self.assertEqual(rel["secrets/pki: sign-verbatim now"], "in_use")
        self.assertEqual(rel["auth/userpass: timing side cha"], "in_use")
        self.assertNotIn("secrets/kv: fix a KV v2 listing", rel)  # bug fix on an engine the cluster doesn't run
        self.assertFalse(any("(enterprise)" in t for t in texts(self.doc)))  # Community cluster

    def test_dependency_advisories_and_go_collapsed(self) -> None:
        self.assertEqual(self.doc["dependency_advisories"]["ids"], ["CVE-2026-0001"])
        self.assertEqual(self.doc["go_toolchain"], ["1.26.7"])
        self.assertFalse(any("Bump Go" in t for t in texts(self.doc)))


class ResourceMode(unittest.TestCase):
    def setUp(self) -> None:
        profile, self.focus, keywords = vc.parse_resources(["secrets/ldap"])
        self.doc = vc.build_document((1, 19, 5), (2, 1, 0), True, RELEASES, profile, META, self.focus, keywords)

    def test_ldap_secrets_not_ldap_auth(self) -> None:
        rel = {x["text"][:25]: x["relevance"] for x in self.doc["impact"]}
        self.assertEqual(rel["secrets/ldap (enterprise)"], "in_use")
        self.assertEqual(rel["ui: Fix LDAP check-out ca"], "mentions")
        self.assertFalse(any(t.startswith("ldap auth") for t in texts(self.doc)))
        self.assertFalse(any("pki" in t for t in texts(self.doc)))

    def test_plugin_versions(self) -> None:
        self.assertEqual(vc.plugin_key("secrets", "openldap"), "secrets/ldap")
        self.assertEqual(vc.bundled_before("secrets/openldap", RELEASES, (1, 19, 5)), "0.15.4")
        pu = [p for p in self.doc["plugin_updates"] if p["component"] == "secrets/openldap"]
        self.assertEqual(pu[0]["plugin_versions"], ["0.18.1"])  # 0.15.4 shipped in 1.19.5 itself

    def test_unknown_resource_rejected(self) -> None:
        res = subprocess.run([sys.executable, str(SCRIPT), "--current", "1.19.5", "--target", "2.1", "--resource", "ldap", "--changelog", str(CHANGELOG)], capture_output=True, text=True)
        self.assertEqual(res.returncode, 1)
        self.assertIn("unknown resource", res.stderr)


PLUGIN_CHANGELOG = """## v0.15.0
### September 11, 2026

* [VAULT-50076] Prepare v0.15.0 Release (#115)

FEATURES:
* Add root token rotation. A new `rotate-root` endpoint performs on-demand
  rotation of the token Vault uses.

## v0.14.1
### March 19, 2026

* Automated dependency upgrades (#107)

## v0.14.0
### March 18, 2026

BUG FIXES:
* Fix team token expiry
"""


class PluginNewerReleases(unittest.TestCase):
    """Plugin releases after the target's bundled version: documented, but not shipped with the target."""

    def setUp(self) -> None:
        pu = {"component": "secrets/terraform", "repo": "https://github.com/hashicorp/vault-plugin-secrets-terraform", "plugin_versions": ["0.14.0", "0.14.1"]}
        with mock.patch.object(vc, "fetch_text", return_value=PLUGIN_CHANGELOG):
            self.pc = vc.plugin_changelog(pu, RELEASES, (1, 19, 5))

    def test_newer_release_flagged_with_date_and_wrapped_text(self) -> None:
        [newer] = self.pc["newer_releases"]
        self.assertEqual((newer["version"], newer["date"]), ("0.15.0", "2026-09-11"))
        self.assertEqual([e["text"] for e in newer["entries"]], ["Add root token rotation. A new `rotate-root` endpoint performs on-demand rotation of the token Vault uses."])

    def test_newer_release_not_in_span(self) -> None:
        self.assertEqual([e["version"] for e in self.pc["entries"]], ["0.14.0"])


API_OLD = """## Configure

| Method | Path |
| :----- | :--- |
| `POST` | `/x/config` |

### Parameters

- `binddn` `(string: <required>)` – The bind DN.
- `certificate` `(string: <optional>)` – CA cert.
- `length` `(int: 64)` – Password length.
"""

API_NEW = """## Configure

| Method | Path |
| :----- | :--- |
| `POST` | `/x/config` |

### Parameters

- `binddn` `(string: "")` – The bind DN.
- `certificate` `(string: "")` – CA cert.
- `self_managed` `(bool: false)` - <EnterpriseAlert inline="true" /> Self-managed mounts.

@include 'rotation.mdx'

**Deprecated Parameters**:

- `length` `(int: 64)` – Password length.

## Migration

| Method | Path |
| :----- | :--- |
| `GET`  | `/x/static-migration` |
| `POST` | `/x/static-migration` |

### Parameters

- `include_role_names` `(boolean: <required>)` – Include names.

## Unlock

| Method | Path |
| :----- | :--- |
| `PUT`  | <nobr>`/x/static-role/:name/unlock`</nobr> |
"""


class ApiDocsDiff(unittest.TestCase):
    def setUp(self) -> None:
        partial = "- `rotation_period` `(string/integer: 0)` – <EnterpriseAlert product=\"vault\" inline /> Rotate."
        fetch = lambda url: partial  # noqa: E731
        changes = vc.diff_api_docs(vc.parse_api_doc(API_OLD, "v1.20.x", fetch), vc.parse_api_doc(API_NEW, "v2.x", fetch))
        self.changes = {(c["change"], c["where"], c["detail"]) for c in changes}

    def test_endpoints_and_parameters(self) -> None:
        self.assertIn(("endpoint added", "PUT /x/static-role/:name/unlock", ""), self.changes)
        self.assertIn(("parameter added", "POST /x/config", "self_managed (bool: false) ENT"), self.changes)
        self.assertIn(("parameter added", "POST /x/config", "rotation_period (string/integer: 0) ENT"), self.changes)  # from the partial
        self.assertIn(("parameter deprecated", "POST /x/config", "length"), self.changes)

    def test_required_to_default_kept_optional_notation_ignored(self) -> None:
        self.assertIn(("type or default changed", "POST /x/config", "binddn: (string: <required>) → (string: \"\")"), self.changes)
        self.assertFalse(any(d.startswith("certificate") for _, _, d in self.changes))

    def test_mixed_methods_named_for_every_method(self) -> None:
        self.assertIn(("parameter added", "GET/POST /x/static-migration", "include_role_names (boolean: <required>)"), self.changes)

    def test_docs_lines_and_skips(self) -> None:
        self.assertEqual((vc.docs_line((1, 20, 0)), vc.docs_line((2, 0, 4))), ("v1.20.x", "v2.x"))
        self.assertTrue(vc.api_diff("secrets/ldap", (2, 0, 0), (2, 1, 0))["status"].startswith("skipped: v2.x docs cover both"))
        self.assertTrue(vc.api_diff("raft", (1, 20, 0), (2, 0, 0))["status"].startswith("skipped: no API docs"))

    def test_kv_doc_path(self) -> None:
        self.assertEqual(vc.api_doc_paths("secrets/kv"), ["api-docs/secret/kv/kv-v2.mdx"])
        fetched: list[str] = []
        fetch = lambda url: fetched.append(url) or API_OLD  # noqa: E731
        ad = vc.api_diff("secrets/kv", (1, 21, 0), (2, 2, 1), fetch)
        self.assertEqual(ad["status"], "read")
        self.assertTrue(all(u.endswith("/api-docs/secret/kv/kv-v2.mdx") for u in fetched))
        self.assertEqual(ad["url"], "https://developer.hashicorp.com/vault/api-docs/v2.x/secret/kv/kv-v2")

    def test_folder_index_fallback_on_404_only(self) -> None:
        def fetch(url: str) -> str:
            if url.endswith("/secret/pki.mdx"):
                raise urllib.error.HTTPError(url, 404, "Not Found", None, None)  # type: ignore[arg-type]
            return API_OLD

        ad = vc.api_diff("secrets/pki", (1, 21, 0), (2, 2, 1), fetch)
        self.assertEqual((ad["status"], ad["url"]), ("read", "https://developer.hashicorp.com/vault/api-docs/v2.x/secret/pki"))

        def down(url: str) -> str:
            raise urllib.error.HTTPError(url, 503, "Unavailable", None, None)  # type: ignore[arg-type]

        self.assertEqual(vc.api_diff("secrets/pki", (1, 21, 0), (2, 2, 1), down)["status"], "unavailable: 503")


class ComparisonMode(unittest.TestCase):
    """Two versions, no audit report and no resource: nothing is known about what's deployed."""

    def setUp(self) -> None:
        self.doc = vc.build_document((1, 19, 5), (2, 1, 0), True, RELEASES, vc.unknown_inventory(), META)

    def test_mode(self) -> None:
        self.assertEqual(self.doc["mode"], "comparison")

    def test_resource_entries_are_if_used_never_not_in_use(self) -> None:
        rel = {x["text"][:30]: x["relevance"] for x in self.doc["impact"]}
        self.assertEqual(rel["secrets/pki: sign-verbatim now"], "if_used")
        self.assertEqual(rel["auth/userpass: timing side cha"], "if_used")
        self.assertNotIn("not_in_use", {x["relevance"] for x in self.doc["impact"]})

    def test_already_shipped_must_read_counted(self) -> None:
        # The router fix is a CHANGES entry in 2.1.0 that 1.19.5 already shipped.
        self.assertEqual(self.doc["span"]["already_shipped_must_read"], {"change": 1})

    def test_current_released_after_target(self) -> None:
        later = vc.build_document((1, 19, 8), (2, 1, 0), True, RELEASES, vc.unknown_inventory(), META)
        self.assertTrue(later["span"]["current_released_after_target"])
        self.assertFalse(self.doc["span"]["current_released_after_target"])

    def test_must_read_grouped_by_component(self) -> None:
        self.assertIn("### secrets/pki (1)", vc.render_markdown(self.doc))

    def test_features_kept_bug_fixes_counted(self) -> None:
        self.assertFalse(any(x["category"] == "bugfix" for x in self.doc["impact"]))
        self.assertGreater(sum(self.doc["other_counts_by_component"].values()), 0)


class Cli(unittest.TestCase):
    def run_script(self, *args: str, env: dict | None = None) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True, env={**os.environ, **(env or {})})

    def test_offline_resource_run(self) -> None:
        with tempfile.TemporaryDirectory() as out:
            res = self.run_script("--current", "1.19.5+ent", "--target", "2.1", "--resource", "secrets/ldap", "--changelog", str(CHANGELOG), "--output-dir", out)
            self.assertEqual(res.returncode, 0, res.stderr)
            json_path, md_path = res.stdout.split()
            for p in (json_path, md_path):
                self.assertEqual(Path(p).stat().st_mode & 0o777, 0o600)
            md = Path(md_path).read_text()
            self.assertIn("Not checked", md)  # --changelog skips plugin changelogs, and says so
            self.assertIn("Dropped", md)

    def test_offline_comparison_run(self) -> None:
        with tempfile.TemporaryDirectory() as out:
            res = self.run_script("--current", "1.19.5", "--target", "2.1", "--changelog", str(CHANGELOG), "--output-dir", out)
            self.assertEqual(res.returncode, 0, res.stderr)
            json_path, md_path = res.stdout.split()
            self.assertIn("vault-upgrade-analyzer-1.19.5-to-2.1.0", json_path)
            md = Path(md_path).read_text()
            self.assertIn("Mode: **comparison**", md)
            self.assertIn("[if_used · 2.1.0] secrets/pki", md)
            self.assertNotIn("## Inventory", md)

    def test_default_output_dir(self) -> None:
        with tempfile.TemporaryDirectory() as cwd:
            res = subprocess.run([sys.executable, str(SCRIPT), "--current", "1.19.5", "--target", "2.1", "--changelog", str(CHANGELOG)], capture_output=True, text=True, cwd=cwd, env={k: v for k, v in os.environ.items() if k != "VAULT_UPGRADE_ANALYZER_DIR"})
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn(".tmp/vault-upgrade-analyzer/", res.stdout)

    def test_current_or_report_required(self) -> None:
        res = self.run_script("--target", "2.1", "--changelog", str(CHANGELOG))
        self.assertEqual(res.returncode, 2)
        self.assertIn("--current", res.stderr)

    def test_report_mode_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            res = self.run_script("--target", "2.1", "--report", str(REPORT), "--changelog", str(CHANGELOG), "--output-dir", tmp)
            self.assertEqual(res.returncode, 0, res.stderr)
            json_path, md_path = res.stdout.split()
            self.assertIn("vault-test-upgrade-analyzer-1.19.5-to-2.1.0", json_path)
            doc = json.loads(Path(json_path).read_text())
            self.assertEqual((doc["mode"], doc["cluster"]["version"], doc["cluster"]["enterprise"]), ("report", "1.19.5", False))
            self.assertIn("secrets/pki: sign-verbatim now rejects CSRs with URI SANs.", texts(doc))
            md = Path(md_path).read_text()
            self.assertIn("## Inventory (from the audit report)", md)
            self.assertIn("older than 24h", md)

    def test_report_with_resource(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            res = self.run_script("--target", "2.1", "--report", str(REPORT), "--resource", "secrets/ldap", "--changelog", str(CHANGELOG), "--output-dir", tmp)
            self.assertEqual(res.returncode, 0, res.stderr)
            doc = json.loads(Path(res.stdout.split()[0]).read_text())
            self.assertEqual((doc["mode"], doc["focus"], doc["cluster"]["version"]), ("resource", ["secrets/ldap"], "1.19.5"))

if __name__ == "__main__":
    unittest.main()
