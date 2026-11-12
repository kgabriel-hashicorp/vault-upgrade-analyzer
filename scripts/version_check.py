#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Offline Vault upgrade impact check.

Report mode (--report without --resource): reads the version, edition and inventory
from a vault-tools namespace audit report (markdown), works out every release between
that version and a target version, parses the Vault CHANGELOG for that span and tags
each entry by whether it touches something the cluster uses.

Resource mode (--resource, with --current or --report): keeps only the
entries about the named resources, plus the changelog of the plugin behind each one
(flagging plugin releases newer than the target's bundled version) and a diff of the
resource's API docs between the source and target release lines.

Comparison mode (--current without --resource): two versions and nothing known about
what's deployed. Entries about a specific auth method, engine or backend are tagged
if_used instead of in_use or not_in_use.

Never talks to Vault. Writes a JSON file and a markdown summary of it; stdout carries
only their paths; diagnostics go to stderr.

Exit codes: 0 ok, 1 fatal (missing input, bad version, changelog unreachable).
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path
from typing import Any

TOOL_NAME = "vault-upgrade-analyzer"
TOOL_VERSION = "0.1.0"
SCHEMA_VERSION = "1.0.0"

RAW_BASE = "https://raw.githubusercontent.com/hashicorp/vault/main"
DOCS_BASE = "https://developer.hashicorp.com/vault/docs"
ENTERPRISE_REPO = "hashicorp/vault-enterprise"

# Older changelog entries live in split files; each covers versions below its bound.
CHANGELOG_FILES = [
    ("CHANGELOG.md", (1, 16, 0)),
    ("CHANGELOG-v1.10-v1.15.md", (1, 10, 0)),
    ("CHANGELOG-pre-v1.10.md", (0, 0, 0)),
]

CATEGORY_BY_SECTION = {
    "BREAKING CHANGES": "breaking",
    "DEPRECATIONS": "deprecation",
    "SECURITY": "security",
    "CHANGES": "change",
    "FEATURES": "feature",
    "IMPROVEMENTS": "improvement",
    "BUG FIXES": "bugfix",
}
# Categories an operator must read before upgrading, whatever the cluster uses.
MUST_READ = {"breaking", "deprecation", "security", "change"}

CLIENT_SIDE = {"ui", "cli", "agent", "proxy", "sdk", "api", "vault/sdk", "go", "containers", "docker", "command", "website", "openapi"}
CLUSTER_WIDE = {
    "core", "identity", "activity", "activitylog", "http", "plugins", "plugin", "consumption-billing", "quotas", "namespaces",
    "seal", "metrics", "telemetry", "ha", "license", "licensing", "rotation", "events", "policies", "acl", "router", "logging",
    "auth", "secrets", "storage", "mounts", "sys", "cluster", "listener", "tls", "census", "billing", "rate-limit",
    "server", "config", "logical", "mfa", "packaging", "secure-plugin-api",
}  # fmt: skip
RAFT_COMPONENTS = {"raft", "storage/raft", "core/raft", "physical/raft", "integrated storage"}
SENTINEL_COMPONENTS = {"sentinel", "policies/sentinel", "core/sentinel", "egp", "rgp"}
# Changelog component name -> mount type as Vault reports it.
TYPE_ALIASES = {"oidc": "jwt", "openldap": "ldap", "kv-v2": "kv", "kvv2": "kv", "ad": "ad"}

RELEASE_RE = re.compile(r"^##\s+v?(\d+)\.(\d+)\.(\d+)(?:\s+(Enterprise))?\s*$", re.IGNORECASE)
DATE_RE = re.compile(r"^#{2,3}\s+([A-Z][a-z]+\s+\d{1,2},\s+\d{4})\s*$")
SECTION_RE = re.compile(r"^([A-Z][A-Z ]+):\s*$")
ENTRY_RE = re.compile(r"^\s*[*-]\s+(.*\S)\s*$")
COMPONENT_RE = re.compile(r"^([A-Za-z0-9_./ -]{1,60}?)\s*(\((?:enterprise|Enterprise|ENT)\))?:\s+(.*)$")
PLUGIN_UPDATE_RE = re.compile(r"^update plugin to\s+\[?v?([\w.\-]+)", re.IGNORECASE)
# Dependency bumps that exist only to pick up an upstream advisory: listed by ID, not one by one.
DEP_BUMP_RE = re.compile(r"^(?:upgrade|update|bump|resolve)\b.*\b(?:CVE-\d{4}-\d+|GHSA-[\w-]+|GO-\d{4}-\d+)", re.IGNORECASE)
GO_BUMP_RE = re.compile(r"^bump go version to\s+([\d.]+)", re.IGNORECASE)
PLUGIN_REPO_RE = re.compile(r"github\.com/hashicorp/(vault-plugin-[\w-]+)/releases")
ADVISORY_RE = re.compile(r"\b(CVE-\d{4}-\d+|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}|GO-\d{4}-\d+)\b", re.IGNORECASE)
TARGET_RE = re.compile(r"^v?(\d+)\.(\d+)(?:\.(\d+|x))?$", re.IGNORECASE)

Version = tuple[int, int, int]


def warn(msg: str) -> None:
    print(msg, file=sys.stderr)


def fatal(msg: str) -> None:
    warn(f"error: {msg}")
    sys.exit(1)


def vstr(v: Version) -> str:
    return ".".join(map(str, v))


# --- audit report (vault-tools namespace audit, markdown) --------------------

REPORT_FRESH_HOURS = 24


def md_sections(text: str) -> list[dict[str, Any]]:
    """Each heading of a markdown report with its body text and tables (rows as header -> cell)."""
    sections: list[dict[str, Any]] = [{"heading": "", "body": [], "tables": []}]
    table: list[list[str]] | None = None
    for line in text.splitlines():
        if line.startswith("#"):
            sections.append({"heading": line.lstrip("#").strip(), "body": [], "tables": []})
            table = None
        elif line.startswith("|"):
            cells = [c.strip().strip("`").strip() for c in line.strip().strip("|").split("|")]
            if table is None:
                table = [cells]
                sections[-1]["tables"].append(table)
            elif not all(re.fullmatch(r":?-+:?", c) for c in cells):
                table.append(cells)
        else:
            table = None
            if line.strip():
                sections[-1]["body"].append(line.strip())
    for s in sections:
        s["tables"] = [[dict(zip(t[0], row)) for row in t[1:]] for t in s["tables"]]
    return sections


def _section(sections: list[dict[str, Any]], heading: str) -> dict[str, Any] | None:
    return next((s for s in sections if s["heading"].lower() == heading.lower()), None)


def _fields(section: dict[str, Any] | None) -> dict[str, str]:
    """A section's Field | Value (or Metric | Value) tables as one dict."""
    out: dict[str, str] = {}
    for table in (section or {}).get("tables", []):
        for row in table:
            vals = list(row.values())
            if len(vals) >= 2:
                out[vals[0]] = vals[1]
    return out


def _count(raw: str | None) -> int | None:
    m = re.match(r"^[\d,]+", (raw or "").strip())
    return int(m[0].replace(",", "")) if m else None


def _types(section: dict[str, Any] | None, column: str) -> dict[str, dict[str, int | None]]:
    """Mount types with counts. Per-namespace built-ins (ns_token, ns_system, ...) fold into their type."""
    types: dict[str, dict[str, int | None]] = {}
    for table in (section or {}).get("tables", []):
        for row in table:
            if not row.get(column):
                continue
            t = row[column].removeprefix("ns_")
            agg = types.setdefault(t, {"mounts": 0, "namespaces": 0})
            agg["mounts"] = (agg["mounts"] or 0) + (_count(row.get("Mounts")) or 0)
            agg["namespaces"] = (agg["namespaces"] or 0) + (_count(row.get("Namespaces")) or 0)  # root and child namespaces don't overlap
    return types


def parse_audit_report(path: Path) -> dict[str, Any]:
    """A vault-tools namespace audit report, reshaped into what classify() and the report use."""
    sections = md_sections(path.read_text())
    header = next((_fields(s) for s in sections if s["tables"]), {})
    summary, health = _fields(_section(sections, "Summary")), _fields(_section(sections, "Cluster health"))
    version_raw = (header.get("Vault version") or "").split(" ")[0]
    m = re.match(r"^v?(\d+)\.(\d+)\.(\d+)", version_raw)
    if not m:
        fatal(f"cannot find the Vault version in {path.name}; is it a vault-tools audit report? Pass --current instead.")
    raft = _section(sections, "Integrated storage (raft)")
    audit = _section(sections, "Audit devices")
    gaps = _section(sections, "Access gaps")
    dr, perf = health.get("DR replication mode"), health.get("Performance replication mode")
    denied = _count(summary.get("Permission denied (skipped)"))
    profile = {
        "auth_types": _types(_section(sections, "Auth methods"), "Auth method type"),
        "secrets_types": _types(_section(sections, "Secrets engines"), "Secrets engine type"),
        "namespaces": _count(summary.get("Namespaces")),
        "raft": True if raft and any(raft["tables"]) else None,
        "replication": {"active": any(v not in (None, "", "disabled", "unknown") for v in (dr, perf)), "dr": dr, "performance": perf},
        "audit_device_types": sorted({r["Type"] for t in audit["tables"] for r in t if r.get("Type")}) if audit else None,
        "sentinel": {"egp": _count(summary.get("Sentinel EGP policies")), "rgp": _count(summary.get("Sentinel RGP policies"))},
        # The report names the database engine's mounts, not which database plugins they use.
        "database_plugins": None,
        "dr_secondary": dr == "secondary",
        "performance_secondary": perf == "secondary",
        "inventory_coverage_complete": bool(gaps and gaps["body"] and gaps["body"][0].lower().startswith("none")) and not denied,
        "access_gaps": [] if not gaps or (gaps["body"] and gaps["body"][0].lower().startswith("none")) else gaps["body"],
    }
    generated = header.get("Generated")
    try:
        when = dt.datetime.strptime(generated or "", "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=dt.UTC)
        age = round((dt.datetime.now(dt.UTC) - when).total_seconds() / 3600, 1)
    except ValueError:
        age = None
    return {
        "version_raw": version_raw,
        "version": (int(m[1]), int(m[2]), int(m[3])),
        "enterprise": "+ent" in version_raw or "enterprise" in (header.get("Vault version") or "").lower(),
        "cluster_name": header.get("Cluster"),
        "generated": generated,
        "age_hours": age,
        "tool": header.get("Tool version"),
        "profile": profile,
    }


def plugin_key(kind: str, mount_type: str) -> str:
    """Normalised changelog component for a mount: ("secrets", "openldap") -> "secrets/ldap"."""
    return f"{'auth' if kind == 'auth' else 'secrets'}/{TYPE_ALIASES.get(mount_type, mount_type)}"


# --- changelog -------------------------------------------------------------


def fetch_text(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": f"{TOOL_NAME}/{TOOL_VERSION}"})
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 - fixed https URLs only
        return resp.read().decode("utf-8", errors="replace")


def fetch_enterprise_changelog() -> tuple[str | None, str]:
    """Read the private vault-enterprise CHANGELOG through the user's gh login, if it has access."""
    if not shutil.which("gh"):
        return None, "skipped: gh CLI not installed"
    try:
        out = subprocess.run(
            ["gh", "api", "-H", "Accept: application/vnd.github.raw", f"repos/{ENTERPRISE_REPO}/contents/CHANGELOG.md"],
            capture_output=True, text=True, timeout=60, check=False,
        )  # fmt: skip
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, f"unavailable: {type(exc).__name__}"
    if out.returncode != 0:
        return None, "unavailable: no access with the current gh login (the repo is private)"
    return out.stdout, "read"


def parse_changelog(text: str, source: str) -> list[dict[str, Any]]:
    releases: list[dict[str, Any]] = []
    rel: dict[str, Any] | None = None
    section = None
    entry: dict[str, Any] | None = None
    for line in text.splitlines():
        if m := RELEASE_RE.match(line):
            rel = {"version": (int(m[1]), int(m[2]), int(m[3])), "enterprise_only": bool(m[4]), "date": None, "entries": [], "source": source}
            releases.append(rel)
            section, entry = None, None
        elif rel is None:
            continue
        elif (m := DATE_RE.match(line)) and rel["date"] is None:
            try:
                rel["date"] = dt.datetime.strptime(re.sub(r"\s+", " ", m[1]), "%B %d, %Y").date().isoformat()
            except ValueError:
                pass
        elif line.startswith("#"):
            section, entry = None, None  # some other heading ends the release body
        elif m := SECTION_RE.match(line):
            section, entry = m[1].strip(), None
        elif section and (m := ENTRY_RE.match(line)) and not line.startswith("    "):
            entry = {"section": section, "text": m[1]}
            rel["entries"].append(entry)
        elif entry is not None and line.strip():
            entry["text"] += " " + line.strip()
        elif not line.strip():
            entry = None
    return releases


def resolve_target(raw: str, releases: list[dict[str, Any]], enterprise: bool) -> Version:
    m = TARGET_RE.match(raw.strip())
    if not m:
        fatal(f"cannot parse target version {raw!r}; use MAJOR.MINOR or MAJOR.MINOR.PATCH, e.g. 1.21 or 2.1.2")
    major, minor = int(m[1]), int(m[2])
    available = sorted({r["version"] for r in releases if enterprise or not r["enterprise_only"]})
    if m[3] and m[3].lower() != "x":
        target = (major, minor, int(m[3]))
        if target not in available:
            fatal(f"version {vstr(target)} is not in the Vault changelog{'' if enterprise else ' (Community releases)'}. Latest known: {vstr(available[-1])}")
        return target
    line = [v for v in available if v[:2] == (major, minor)]
    if not line:
        fatal(f"no {major}.{minor}.x release in the Vault changelog. Latest known: {vstr(available[-1])}")
    return line[-1]


# --- classification ----------------------------------------------------------


def split_component(text: str) -> tuple[str, bool, str]:
    m = COMPONENT_RE.match(text)
    if not m:
        return "", False, text
    return m[1].strip().lower(), bool(m[2]), m[3]


def unknown_inventory() -> dict[str, Any]:
    """Comparison mode's profile: no cluster, so nothing is known to be deployed."""
    return {
        "inventory_unknown": True, "auth_types": {}, "secrets_types": {}, "namespaces": None, "raft": False,
        "replication": {"active": False, "dr": None, "performance": None}, "audit_device_types": [], "sentinel": {"egp": 0, "rgp": 0},
    }  # fmt: skip


def classify(component: str, profile: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
    """Return (relevance, matched resource). Relevance: in_use, not_in_use, if_used, cluster_wide, client_side, unclassified."""
    relevance, resource = _classify_known(component, profile)
    # Without an inventory, "not in this cluster" really means "applies if you use it".
    if profile.get("inventory_unknown") and relevance == "not_in_use":
        return "if_used", resource
    return relevance, resource


def _classify_known(component: str, profile: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
    auth, secrets = profile["auth_types"], profile["secrets_types"]
    if not component:
        return "cluster_wide", None
    if m := re.match(r"^([\w-]+) (auth|secrets?)(?: engine)?$", component):
        component = f"{'auth' if m[2] == 'auth' else 'secrets'}/{m[1]}"
    if component in RAFT_COMPONENTS:
        return ("in_use", {"kind": "storage", "type": "raft"}) if profile["raft"] else ("not_in_use", None)
    if component in SENTINEL_COMPONENTS:
        count = (profile["sentinel"]["egp"] or 0) + (profile["sentinel"]["rgp"] or 0)
        return ("in_use", {"kind": "sentinel", "policies": count}) if count else ("not_in_use", None)
    parts = component.replace(" ", "/").split("/")
    head = parts[0]
    sub = TYPE_ALIASES.get(parts[1], parts[1]) if len(parts) > 1 else None
    if head == "replication" or component.startswith("core/replication"):
        return ("in_use", {"kind": "replication", **profile["replication"]}) if profile["replication"]["active"] else ("not_in_use", None)
    if head == "audit":
        types = profile["audit_device_types"]
        if types is None:
            return "cluster_wide", None
        if sub and sub in types:
            return "in_use", {"kind": "audit_device", "type": sub}
        return ("in_use", {"kind": "audit_device", "types": types}) if types and not sub else ("not_in_use" if types is not None and sub else "cluster_wide", None)
    if head == "auth" and sub:
        if (sub == "token" and profile.get("token_implicit", True)) or sub in auth:
            return "in_use", {"kind": "auth", "type": sub, **(auth.get(sub) or {})}
        return "not_in_use", {"kind": "auth", "type": sub}
    if head in ("secrets", "secret") and sub:
        if sub in secrets:
            return "in_use", {"kind": "secrets", "type": sub, **secrets[sub]}
        return "not_in_use", {"kind": "secrets", "type": sub}
    if head == "database":
        # Database plugins (database/snowflake, ...) run inside the database engine; plugin names are not collected.
        wanted = profile.get("database_plugins")
        if wanted is not None and sub and sub not in wanted:
            return "not_in_use", {"kind": "secrets", "type": "database", "plugin": sub}
        if "database" in secrets:
            return "in_use", {"kind": "secrets", "type": "database", "plugin": sub, **secrets["database"], "note": "database engine in use; which database plugins its connections use is not collected"}
        return "not_in_use", {"kind": "secrets", "type": "database", "plugin": sub}
    if head in ("storage", "physical") and sub:
        if profile["raft"]:
            return "not_in_use", {"kind": "storage", "type": sub}
        return "cluster_wide", {"kind": "storage", "type": sub, "note": "storage backend not identified in the audit report"}
    bare = TYPE_ALIASES.get(head, head)
    if bare in secrets:
        return "in_use", {"kind": "secrets", "type": bare, **secrets[bare]}
    if bare in auth:
        return "in_use", {"kind": "auth", "type": bare, **auth[bare]}
    if head in CLIENT_SIDE or component in CLIENT_SIDE:
        return "client_side", None
    if head in CLUSTER_WIDE or head.startswith("core"):
        return "cluster_wide", None
    return "unclassified", None


# --- resource mode -----------------------------------------------------------

RESOURCE_HELP = "secrets/<type>, auth/<type>, database/<plugin>, audit/<type>, raft, replication or sentinel (e.g. secrets/ldap, auth/jwt, database/postgresql)"


def parse_resources(specs: list[str]) -> tuple[dict[str, Any], list[str], set[str]]:
    """Build a profile that 'uses' only the named resources, plus the words to look for in other entries."""
    profile: dict[str, Any] = {
        "auth_types": {}, "secrets_types": {}, "namespaces": None, "raft": None,
        "replication": {"active": False, "dr": None, "performance": None},
        "audit_device_types": [], "sentinel": {"egp": 0, "rgp": 0}, "database_plugins": set(), "token_implicit": False,
    }  # fmt: skip
    names, keywords = [], set()
    for spec in specs:
        s = spec.strip().lower().replace(" ", "")
        head, _, sub = s.partition("/")
        sub = TYPE_ALIASES.get(sub, sub)
        aliases = {sub} | {k for k, v in TYPE_ALIASES.items() if v == sub}
        if head in ("secrets", "secret") and sub:
            profile["secrets_types"][sub] = {}
            names.append(f"secrets/{sub}")
            keywords |= aliases
        elif head == "auth" and sub:
            profile["auth_types"][sub] = {}
            names.append(f"auth/{sub}")
            keywords |= aliases
        elif head == "database" and sub:
            profile["secrets_types"]["database"] = {}
            profile["database_plugins"].add(sub)
            names.append(f"database/{sub}")
            keywords.add(sub)
        elif head == "audit" and sub:
            profile["audit_device_types"].append(sub)
            names.append(f"audit/{sub}")
        elif s in ("raft", "storage/raft", "integratedstorage"):
            profile["raft"] = True
            names.append("raft")
            keywords |= {"raft", "integrated storage", "autopilot"}
        elif s == "replication":
            profile["replication"]["active"] = True
            names.append("replication")
            keywords.add("replication")
        elif s == "sentinel":
            profile["sentinel"]["egp"] = 1
            names.append("sentinel")
            keywords |= {"sentinel", "egp", "rgp"}
        else:
            fatal(f"unknown resource {spec!r}; use {RESOURCE_HELP}")
    if not profile["database_plugins"]:
        profile["database_plugins"] = None
    else:
        profile["database_plugins"] = sorted(profile["database_plugins"])
    return profile, names, keywords


def mentions(text: str, keywords: set[str], profile: dict[str, Any]) -> bool:
    for k in keywords:
        if not re.search(rf"\b{re.escape(k)}\b", text, re.IGNORECASE):
            continue
        kw = re.escape(k)
        # "ldap auth", "auth/ldap", "LDAP and username/password" logins vs "LDAP secrets engine", "secrets/ldap".
        is_auth = re.search(rf"\bauth/{kw}\b|\b{kw} auth\b|\b{kw} (?:user|login)", text, re.IGNORECASE)
        is_secrets = re.search(rf"\bsecrets?/{kw}\b|\b{kw} secrets?\b|\b{kw} (?:static|dynamic|library|check-?out)", text, re.IGNORECASE)
        if k in profile["secrets_types"] and k not in profile["auth_types"] and is_auth and not is_secrets:
            continue
        if k in profile["auth_types"] and k not in profile["secrets_types"] and is_secrets and not is_auth:
            continue
        return True
    return False


# Housekeeping lines in plugin changelogs that say nothing about behaviour.
PLUGIN_NOISE_RE = re.compile(
    r"dependenc|\bbump\b|changelog|copyright|compliance|workflow|changie|backport|\btests?\b|go version|upgrade go|update go|^chore|pr template|ci\b|prepare v?[\d.]+ release",
    re.IGNORECASE,
)


def plugin_semver(v: str) -> tuple[int, ...]:
    return tuple(int(n) for n in re.findall(r"\d+", v)[:3])


def bundled_before(component: str, releases: list[dict[str, Any]], current: Version) -> str | None:
    """Plugin version Vault bundled at `current`: the last 'Update plugin to' entry in a release at or before it."""
    best: tuple[Version, str] | None = None
    for r in releases:
        if r["version"] > current:
            continue
        for e in r["entries"]:
            comp, _, body = split_component(e["text"])
            if comp == component and (m := PLUGIN_UPDATE_RE.match(body)) and (best is None or r["version"] >= best[0]):
                best = (r["version"], m[1])
    return best[1] if best else None


def plugin_changelog(pu: dict[str, Any], releases: list[dict[str, Any]], current: Version) -> dict[str, Any]:
    repo = pu["repo"].rsplit("/", 1)[-1]
    # Nothing records the running plugin version, so the start is the version bundled with `current`.
    start = bundled_before(pu["component"], releases, current)
    end = pu["plugin_versions"][-1]
    result: dict[str, Any] = {
        "component": pu["component"], "repo": pu["repo"], "from": start, "to": end, "entries": [], "noise_dropped": 0,
        "from_source": "estimated" if start else None,
    }  # fmt: skip
    try:
        text = fetch_text(f"https://raw.githubusercontent.com/hashicorp/{repo}/main/CHANGELOG.md")
    except OSError as exc:
        code = getattr(exc, "code", None)
        result["status"] = "unavailable: not a public repo (private or moved)" if code == 404 else f"unavailable: {type(exc).__name__}"
        return result
    lo = plugin_semver(start) if start else plugin_semver(pu["plugin_versions"][0])
    hi, version, section, keep, newer = plugin_semver(end), None, None, False, False
    last: dict[str, Any] | None = None
    seen: set[tuple[int, ...]] = set()
    # Releases after the target's bundled version: the docs for the target's line may already
    # describe them, but their changes don't ship with the target.
    result["newer_releases"] = []
    for line in text.splitlines():
        if m := re.match(r"^##\s+v?(\d+\.\d+\.\d+)", line):
            version, section, last = m[1], None, None
            seen.add(plugin_semver(version))
            v = plugin_semver(version)
            # Without a known starting point, include the first bundled version itself.
            keep = (lo < v <= hi) if start else (lo <= v <= hi)
            newer = v > hi
            if newer:
                result["newer_releases"].append({"version": version, "date": None, "entries": []})
        elif newer and (m := DATE_RE.match(line)) and result["newer_releases"][-1]["date"] is None:
            result["newer_releases"][-1]["date"] = dt.datetime.strptime(m[1], "%B %d, %Y").date().isoformat()
        elif (keep or newer) and (m := SECTION_RE.match(line)):
            section = m[1].strip().lower()
        elif (keep or newer) and (m := re.match(r"^[*-]\s+(.*\S)", line)):
            last = None
            if PLUGIN_NOISE_RE.search(m[1]):
                result["noise_dropped"] += keep
            else:
                last = {"version": version, "section": section, "text": m[1]}
                (result["entries"] if keep else result["newer_releases"][-1]["entries"]).append(last)
        elif last is not None and re.match(r"^\s+[^\s*-]", line):
            # A wrapped entry continues on indented lines.
            last["text"] += " " + line.strip()
        elif not line.strip() or line.startswith(("#", "*", "-")):
            last = None
    result["newer_releases"].sort(key=lambda r: plugin_semver(r["version"]))
    result["status"] = "read"
    # Patch releases are often noted only on release branches, not in main's CHANGELOG.
    result["missing_versions"] = [v for v in pu["plugin_versions"] if plugin_semver(v) not in seen and plugin_semver(v) > lo]
    return result


# --- API docs diff -----------------------------------------------------------

# The versioned developer.hashicorp.com docs, as the markdown they're built from.
API_DOCS_RAW = "https://raw.githubusercontent.com/hashicorp/web-unified-docs/main/content/vault/{line}/content/{path}"
ENDPOINT_RE = re.compile(r"^\|\s*`([A-Z]+)`\s*\|\s*(?:<nobr>)?`([^`]+)`")
PARAM_RE = re.compile(r"^\s*[-*]\s+`([\w.\-\[\]]+)`\s+`\(([^)]*)\)`(.*)$")
INCLUDE_RE = re.compile(r"^@include\s+'([^']+)'")
API_DIFF_LIMIT = 40


# Resources whose API page isn't at api-docs/<secret|auth>/<type>.mdx. KV's folder has one page
# per KV version (kv-v1.mdx, kv-v2.mdx); the diff uses v2, the versioned engine.
API_DOC_OVERRIDES = {"secrets/kv": "api-docs/secret/kv/kv-v2.mdx"}


def api_doc_paths(resource: str) -> list[str]:
    """Candidate doc paths, tried in order: a page per type, or a folder with an index page (pki, ...)."""
    if resource in API_DOC_OVERRIDES:
        return [API_DOC_OVERRIDES[resource]]
    head, _, sub = resource.partition("/")
    if head in ("secrets", "auth") and sub:
        folder = "secret" if head == "secrets" else "auth"
        return [f"api-docs/{folder}/{sub}.mdx", f"api-docs/{folder}/{sub}/index.mdx"]
    if head == "database" and sub:
        return [f"api-docs/secret/databases/{sub}.mdx"]
    return []


def docs_line(v: Version) -> str:
    """Docs directory for a release line: one per 1.x minor, one for all of 2.x."""
    return f"v{v[0]}.x" if v[0] >= 2 else f"v{v[0]}.{v[1]}.x"


def parse_api_doc(text: str, line: str, fetch: Any = None) -> dict[str, dict[str, Any]]:
    """{endpoint label: {"endpoints": [...], "params": {name: {"spec", "ent", "deprecated"}}}}.

    One group per endpoint table: a ## section can hold several endpoints, each with its own
    parameter list, and parameters belong to the table above them."""
    fetch = fetch or fetch_text
    sections: list[dict[str, Any]] = []
    cur: dict[str, Any] | None = None
    deprecated, in_table = False, False
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        raw = lines[i]
        i += 1
        if m := INCLUDE_RE.match(raw):
            # One level of partials (shared parameter lists such as the rotation fields).
            try:
                lines[i:i] = fetch(API_DOCS_RAW.format(line=line, path=f"partials/{m[1]}")).splitlines()
            except OSError:
                pass
            continue
        table_row = raw.startswith("|")
        if raw.startswith("## "):
            cur = {"heading": raw[3:].strip(), "endpoints": [], "params": {}}
            sections.append(cur)
            deprecated = False
        elif cur is None:
            pass
        elif raw.startswith("### "):
            deprecated = "deprecat" in raw.lower()
        elif re.match(r"^\*\*deprecated", raw.strip(), re.IGNORECASE):
            deprecated = True
        elif m := ENDPOINT_RE.match(raw):
            if cur["endpoints"] and not in_table:
                # A second endpoint table in the same section starts a new group.
                cur = {"heading": cur["heading"], "endpoints": [], "params": {}}
                sections.append(cur)
                deprecated = False
            cur["endpoints"].append(f"{m[1]} {m[2]}")
        elif (m := PARAM_RE.match(raw)) and m[1] not in cur["params"]:
            cur["params"][m[1]] = {
                "spec": re.sub(r"\s+", " ", m[2]).strip(),
                "ent": "EnterpriseAlert" in m[3],
                "deprecated": deprecated or bool(re.search(r"\bdeprecated\b", m[3], re.IGNORECASE)),
            }
        in_table = table_row
    # Key by endpoint so a renamed heading isn't read as a removed endpoint. A table can list
    # several methods without saying which takes the parameters, so the key names the write
    # path with every method listed for it ("GET/POST /ldap/static-migration").
    def key(s: dict[str, Any]) -> str:
        if not s["endpoints"]:
            return s["heading"]
        writes = [e for e in s["endpoints"] if e.split()[0] in ("POST", "PUT")]
        path = (writes or s["endpoints"])[0].split(" ", 1)[1]
        return "/".join(e.split()[0] for e in s["endpoints"] if e.split(" ", 1)[1] == path) + " " + path

    return {key(s): s for s in sections}


def same_spec(a: str, b: str) -> bool:
    """`(string: <optional>)` and `(string: "")` are the same parameter written two ways."""
    norm = lambda s: re.sub(r":\s*(?:<optional>|\"\")\s*$", ": <optional>", s)  # noqa: E731
    return norm(a) == norm(b)


def diff_api_docs(old: dict[str, dict[str, Any]], new: dict[str, dict[str, Any]]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    old_eps = {e for s in old.values() for e in s["endpoints"]}
    new_eps = {e for s in new.values() for e in s["endpoints"]}
    changes += [{"change": "endpoint added", "where": e, "detail": ""} for e in sorted(new_eps - old_eps)]
    changes += [{"change": "endpoint removed", "where": e, "detail": ""} for e in sorted(old_eps - new_eps)]
    for key in sorted(old.keys() | new.keys()):
        op = (old.get(key) or {}).get("params", {})
        np_ = (new.get(key) or {}).get("params", {})
        for name in sorted(np_.keys() - op.keys()):
            p = np_[name]
            changes.append({"change": "parameter added", "where": key, "detail": f"{name} ({p['spec']})" + (" ENT" if p["ent"] else "") + (" deprecated" if p["deprecated"] else "")})
        for name in sorted(op.keys() - np_.keys()):
            if key in new:  # parameters of a removed endpoint are covered by "endpoint removed"
                changes.append({"change": "parameter removed", "where": key, "detail": name})
        for name in sorted(op.keys() & np_.keys()):
            a, b = op[name], np_[name]
            if not same_spec(a["spec"], b["spec"]):
                changes.append({"change": "type or default changed", "where": key, "detail": f"{name}: ({a['spec']}) → ({b['spec']})"})
            if b["deprecated"] and not a["deprecated"]:
                changes.append({"change": "parameter deprecated", "where": key, "detail": name})
    return changes


def api_diff(resource: str, current: Version, target: Version, fetch: Any = None) -> dict[str, Any]:
    fetch = fetch or fetch_text
    paths, src, dst = api_doc_paths(resource), docs_line(current), docs_line(target)
    result: dict[str, Any] = {"resource": resource, "from_docs": src, "to_docs": dst, "changes": []}
    if not paths:
        result["status"] = "skipped: no API docs page for this resource type"
        return result

    def page_url(path: str) -> str:
        page = path.removesuffix(".mdx").removesuffix("/index")
        return f"https://developer.hashicorp.com/vault/{page.replace('api-docs/', f'api-docs/{dst}/', 1)}"

    result["url"] = page_url(paths[0])
    if src == dst:
        result["status"] = f"skipped: {src} docs cover both versions"
        return result

    def first_page(line: str) -> tuple[str, str]:
        """The first candidate that exists on this docs line; only a 404 moves on to the next."""
        for i, path in enumerate(paths):
            try:
                return path, fetch(API_DOCS_RAW.format(line=line, path=path))
            except OSError as exc:
                if getattr(exc, "code", None) != 404 or i == len(paths) - 1:
                    raise
        raise AssertionError("unreachable")

    try:
        _, old_text = first_page(src)
        new_path, new_text = first_page(dst)
        old, new = parse_api_doc(old_text, src, fetch), parse_api_doc(new_text, dst, fetch)
    except OSError as exc:
        result["status"] = f"unavailable: {getattr(exc, 'code', None) or type(exc).__name__}"
        return result
    result["url"] = page_url(new_path)
    result["changes"] = diff_api_docs(old, new)
    result["status"] = "read"
    return result


# --- markdown summary --------------------------------------------------------

LINK_RE = re.compile(r"\[([^\]]+)\]\([^)]+\)")


def entry_key(text: str) -> str:
    """Comparable form of a changelog entry: backports of one change differ only in links and PR refs."""
    return clean(text, 10**6).lower()


def clean(text: str, limit: int) -> str:
    t = LINK_RE.sub(r"\1", text)
    t = re.sub(r"\s*[\[(]+\s*(?:GH-\d+|[0-9a-f]{8,40})(?:\s*,\s*(?:GH-\d+|HCSEC-[\d-]+))*\s*[\])]+", "", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t if len(t) <= limit else t[: limit - 1].rstrip() + "…"


def render_markdown(doc: dict[str, Any]) -> str:
    c, t, span = doc["cluster"], doc["target"], doc["span"]
    resource_mode = doc["mode"] == "resource"
    label = {"resource": ", ".join(doc["focus"] or []), "comparison": "version comparison"}.get(doc["mode"]) or c["name"] or "cluster"
    title = f"Vault {c['version']} → {t['resolved']}: {label}"
    out = [f"# {title}", ""]
    out.append(f"- Mode: **{doc['mode']}**" + (f" (resources: {', '.join(doc['focus'])})" if resource_mode else ""))
    out.append(f"- Edition: {'Enterprise (Enterprise-only entries included, marked ENT)' if c['enterprise'] else 'Community (Enterprise-only entries excluded)'}")
    out.append(f"- Target: {t['resolved']} (requested {t['requested']}, released {t['release_date'] or 'unknown'}){' — crosses a major version' if t['major_upgrade'] else ''}")
    out.append(f"- Span: {len(span['releases'])} releases across lines {', '.join(span['minor_lines'])}")
    if span.get("already_shipped_dropped"):
        must = ", ".join(f"{n} {cat}" for cat, n in (span.get("already_shipped_must_read") or {}).items())
        out.append(
            f"- Dropped {span['already_shipped_dropped']} entries already shipped in {c['version']} (backports repeated in later releases)"
            + (f"; distinct must-read entries among them: {must}" if must else "")
        )
    if span.get("current_released_after_target"):
        out.append(
            f"- **Note**: {c['version']} was released after {t['resolved']}, so fixes in {c['version']} may not be in {t['resolved']} yet. "
            "Check for a newer patch of the target line."
        )
    if span["excluded_released_after_target"]:
        out.append(f"- Excluded (released after the target): {', '.join(span['excluded_released_after_target'])}")
    srcs = ", ".join(f"{s['source'].rsplit('/', 1)[-1]} ({s['status']})" for s in doc["sources"]["changelog"])
    out.append(f"- Sources: {srcs}; vault-enterprise repo: {doc['sources']['enterprise_repo']}")
    if doc.get("inputs", {}).get("report"):
        inp = doc["inputs"]
        age = f", {inp['report_age_hours']}h ago" if inp.get("report_age_hours") is not None else ""
        stale = " — **older than 24h; the cluster may have changed**" if (inp.get("report_age_hours") or 0) > REPORT_FRESH_HOURS else ""
        out.append(f"- Audit report: `{inp['report']}` (generated {inp.get('report_generated') or 'at an unknown time'}{age} by {inp.get('collected_by')}){stale}")
    out.append("")

    if doc["mode"] == "report":
        p = doc["profile"]
        fmt = lambda d: ", ".join(f"{k} ({v.get('mounts', '?')} mounts)" for k, v in d.items()) or "none"  # noqa: E731
        out += [
            "## Inventory (from the audit report)",
            "",
            f"- Auth methods: {fmt(p['auth_types'])}",
            f"- Secrets engines: {fmt(p['secrets_types'])}",
            f"- Namespaces: {p['namespaces']}; Raft: {bool(p['raft'])}; replication: DR {p['replication']['dr']}, performance {p['replication']['performance']}",
            f"- Audit device types: {p['audit_device_types']}; Sentinel EGP/RGP: {p['sentinel']['egp']}/{p['sentinel']['rgp']}",
            f"- Performance secondary: {p['performance_secondary']}; DR secondary: {p['dr_secondary']}; inventory coverage complete: {p['inventory_coverage_complete']}",
            "- Not in the report: plugin versions, database plugin names, per-mount configuration",
        ]
        out += [f"- Access gap: {g}" for g in p.get("access_gaps") or []]
        out.append("")

    out += ["## Docs to read", ""]
    for d in doc["docs"]:
        out.append(f"- {d['line']}: {d['important_changes']}" + (f" · release notes: {d['release_notes']}" if d["release_notes"] else ""))
    out.append("")

    out += ["## Counts (category × relevance, all entries in span)", ""]
    rels = ["in_use", "mentions", "if_used", "cluster_wide", "unclassified", "client_side", "not_in_use"]
    used = [r for r in rels if any(r in v for v in doc["summary"]["by_category"].values())]
    out.append("| category | " + " | ".join(used) + " |")
    out.append("|---|" + "---|" * len(used))
    for cat, v in doc["summary"]["by_category"].items():
        out.append(f"| {cat} | " + " | ".join(str(v.get(r, 0)) for r in used) + " |")
    out.append("")

    def line(x: dict[str, Any], limit: int) -> str:
        tags = [x["relevance"], x["first_version"]] + (["ENT"] if x["enterprise_only"] else [])
        return f"- [{' · '.join(tags)}] {clean(x['text'], limit)}"

    must = [x for x in doc["impact"] if x["category"] in MUST_READ]
    rest = [x for x in doc["impact"] if x["category"] not in MUST_READ]
    titles = {"breaking": "Breaking changes", "deprecation": "Deprecations", "security": "Security", "change": "Behaviour changes"}
    for cat in ("breaking", "deprecation", "security", "change"):
        xs = [x for x in must if x["category"] == cat]
        if not xs:
            continue
        out += [f"## {titles[cat]} ({len(xs)})", ""]
        if doc["mode"] != "comparison":
            out += [line(x, 420) for x in xs] + [""]
            continue
        # A whole release span has many must-read entries; grouping by component makes them scannable.
        by_comp: dict[str, list[dict[str, Any]]] = {}
        for x in xs:
            by_comp.setdefault(x["component"] or "(none)", []).append(x)
        for comp, group in sorted(by_comp.items()):
            out += [f"### {comp} ({len(group)})"] + [line(x, 420) for x in group] + [""]
    if rest:
        scope = {"resource": " for the resource", "comparison": " (new features; improvements and fixes are counted below)"}.get(doc["mode"], " for components in use")
        out += [f"## Features, improvements and fixes{scope} ({len(rest)})", ""]
        groups: dict[str, list[dict[str, Any]]] = {}
        for x in rest:
            groups.setdefault(x["component"] or "(none)", []).append(x)
        for comp, xs in sorted(groups.items(), key=lambda kv: -len(kv[1])):
            out.append(f"### {comp} ({len(xs)})")
            out += [f"- [{x['category']} · {x['first_version']}{' · ENT' if x['enterprise_only'] else ''}] {clean(x['text'], 220)}" for x in xs]
            out.append("")

    pus = [pu for pu in doc["plugin_updates"] if pu["relevance"] in ("in_use", "if_used")]
    if pus:
        out += ["## Plugin updates" + (" (apply if you use the plugin)" if doc["mode"] == "comparison" else " for components in use"), ""]
        for pu in pus:
            repo = f" — {pu['repo']}" if pu.get("repo") else ""
            out.append(f"- {pu['component']}: {' → '.join(pu['plugin_versions'])}{repo}")
        out.append("")
    for pc in doc.get("plugin_changelogs") or []:
        span_txt = f"{pc['from'] or '?'}{' (estimated)' if pc.get('from_source') == 'estimated' else ''} → {pc['to']}"
        out += [f"## Plugin changelog: {pc['component']} ({span_txt})", "", f"Source: {pc['repo']}/blob/main/CHANGELOG.md ({pc['status']}; {pc['noise_dropped']} housekeeping lines dropped)", ""]
        out += [f"- [{e['version']}{' · ' + e['section'] if e['section'] else ''}] {clean(e['text'], 240)}" for e in pc["entries"]] or (
            [] if pc["status"].startswith("skipped") else ["- no behaviour changes listed"]
        )
        if pc.get("newer_releases"):
            out.append(f"- **newer than the target's bundled {pc['to']}, so not in {t['resolved']}** (the docs for the target's line may already describe these):")
            for r in pc["newer_releases"]:
                notes = "; ".join(clean(e["text"], 200) for e in r["entries"][:4]) or "housekeeping only"
                out.append(f"  - {r['version']} ({r['date'] or 'date unknown'}): {notes}")
        if pc.get("missing_versions"):
            out.append(f"- note: {', '.join(pc['missing_versions'])} not in the plugin's main CHANGELOG (likely noted on a release branch or in GitHub releases); check {pc['repo']}/releases")
        if not pc["from"]:
            out.append(f"- note: the plugin version bundled with {c['version']} wasn't found in the Vault changelog, so this starts at the first update in the span")
        out.append("")
    for ad in doc.get("api_diffs") or []:
        out += [f"## API changes: {ad['resource']} (docs {ad['from_docs']} → {ad['to_docs']})", ""]
        if ad["status"] != "read":
            out += [f"- {ad['status']}", ""]
            continue
        out.append(f"Source: {ad['url']}. Docs are per release line, not per patch" + (
            f"; the {ad['to_docs']} docs cover every {ad['to_docs'][1:-2]}.x minor, so a change may postdate {t['resolved']} (compare with newer plugin releases above)." if ad["to_docs"].count(".") == 1 else "."))
        out.append("")
        out += [f"- {ch['change']}: {ch['where']}" + (f" — {ch['detail']}" if ch["detail"] else "") for ch in ad["changes"][:API_DIFF_LIMIT]] or ["- no endpoint or parameter changes"]
        if len(ad["changes"]) > API_DIFF_LIMIT:
            out.append(f"- … {len(ad['changes']) - API_DIFF_LIMIT} more in the JSON (api_diffs)")
        out.append("")
    if doc.get("plugin_changelogs_skipped"):
        out += ["## Not checked", "", f"- {doc['plugin_changelogs_skipped'].capitalize()}. Plugin updates above list versions only.", ""]
    adv = doc["dependency_advisories"]
    out.append(f"## Dependency advisories ({adv['count']})")
    out += ["", ", ".join(adv["ids"]) or "none", ""]
    if doc["go_toolchain"]:
        out += [f"Go toolchain: {doc['go_toolchain'][0]} → {doc['go_toolchain'][-1]}", ""]
    if doc.get("other_counts_by_component") and not resource_mode:
        top = list(doc["other_counts_by_component"].items())[:20]
        out += ["## Not in this summary (counts by component)", "", ", ".join(f"{k}: {v}" for k, v in top), ""]
    out.append("Full entries (all fields, every version they shipped in) are in the JSON file of the same name.")
    return "\n".join(out) + "\n"


# --- assembly ----------------------------------------------------------------


def docs_links(minor_lines: list[tuple[int, int]]) -> list[dict[str, str]]:
    links, seen = [], set()
    for major, minor in minor_lines:
        if major >= 2:
            # From 2.x the docs keep one page per major line, not per minor.
            key = label = f"{major}.x"
            ic, rn = f"{DOCS_BASE}/v{major}.x/updates/important-changes", f"{DOCS_BASE}/v{major}.x/updates/release-notes"
        elif minor >= 16:
            key, label = f"{major}.{minor}", f"{major}.{minor}.x"
            ic, rn = f"{DOCS_BASE}/v{major}.{minor}.x/updates/important-changes", f"{DOCS_BASE}/v{major}.{minor}.x/updates/release-notes"
        else:
            key, label = f"{major}.{minor}", f"{major}.{minor}.x"
            ic, rn = f"{DOCS_BASE}/v{major}.{minor}.x/upgrading/upgrade-to-{major}.{minor}.x", ""
        if key in seen:
            continue
        seen.add(key)
        links.append({"line": label, "important_changes": ic, "release_notes": rn})
    links.append({"line": "lts", "important_changes": f"{DOCS_BASE}/updates/lts-tracker", "release_notes": ""})
    return links


def build_document(
    current: Version,
    target: Version,
    enterprise: bool,
    releases: list[dict[str, Any]],
    profile: dict[str, Any],
    meta: dict[str, Any],
    focus: list[str] | None = None,
    keywords: set[str] | None = None,
) -> dict[str, Any]:
    """Report mode when focus is None; resource mode keeps only entries for the focus resources.
    Comparison mode when the profile is unknown_inventory(): no report, no resource."""
    comparison = bool(profile.get("inventory_unknown"))
    target_rel = next(r for r in releases if r["version"] == target)
    cutoff = target_rel["date"]
    current_date = next((r["date"] for r in releases if r["version"] == current), None)
    in_span, excluded = [], []
    for r in sorted({r["version"]: r for r in releases}.values(), key=lambda r: r["version"]):
        if not (current < r["version"] <= target) or (r["enterprise_only"] and not enterprise):
            continue
        # A patch on an older line shipped after the target may carry fixes the target doesn't have yet.
        if cutoff and r["date"] and r["date"] > cutoff:
            excluded.append(vstr(r["version"]))
            continue
        in_span.append(r)

    # Fixes are backported: a newer release repeats entries the current version's own line already
    # shipped. Those aren't changes for this upgrade, so they're dropped (and counted).
    shipped = {
        entry_key(e["text"])
        for r in releases
        if r["version"][:2] == current[:2] and r["version"] <= current and (enterprise or not r["enterprise_only"])
        for e in r["entries"]
    }
    already_shipped = 0
    shipped_must_read: dict[str, set[str]] = {}
    merged: dict[str, dict[str, Any]] = {}
    plugin_updates: dict[str, dict[str, Any]] = {}
    resources: dict[str, Any] = {}
    advisories: dict[str, set[str]] = {}
    go_versions: set[str] = set()
    for r in in_span:
        for e in r["entries"]:
            component, ent_tag, body = split_component(e["text"])
            if ent_tag and not enterprise:
                continue
            key = entry_key(e["text"])
            category = CATEGORY_BY_SECTION.get(e["section"], "other")
            if key in shipped:
                already_shipped += 1
                if category in MUST_READ:
                    shipped_must_read.setdefault(category, set()).add(key)
                continue
            relevance, resource = classify(component, profile)
            # Resource mode: an entry filed under another component (core, ui, ...) can still be about the resource.
            if keywords and relevance != "in_use" and not (resource and resource.get("kind") in ("auth", "secrets")) and mentions(e["text"], keywords, profile):
                relevance = "mentions"
            if resource and component and relevance == "in_use":
                resources[component] = resource
            if pm := PLUGIN_UPDATE_RE.match(body):
                pu = plugin_updates.setdefault(component, {"component": component, "relevance": relevance, "plugin_versions": []})
                if rm := PLUGIN_REPO_RE.search(body):
                    pu["repo"] = f"https://github.com/hashicorp/{rm[1]}"
                if pm[1] not in pu["plugin_versions"]:
                    pu["plugin_versions"].append(pm[1])
                continue
            if gm := GO_BUMP_RE.match(body):
                go_versions.add(gm[1].rstrip("."))
                continue
            if category == "security" and relevance != "in_use" and DEP_BUMP_RE.match(body):
                for adv in ADVISORY_RE.findall(body):
                    advisories.setdefault(adv.upper(), set()).add(component or "(none)")
                continue
            item = merged.get(key)
            if item is None:
                item = merged[key] = {
                    "category": category,
                    "relevance": relevance,
                    "component": component or None,
                    "enterprise_only": ent_tag or r["enterprise_only"],
                    "text": e["text"],
                    "versions": [],
                }
            item["versions"].append(vstr(r["version"]))

    order = {c: i for i, c in enumerate(["breaking", "deprecation", "security", "change", "feature", "improvement", "bugfix", "other"])}
    rel_order = {"in_use": 0, "mentions": 1, "if_used": 2, "cluster_wide": 3, "unclassified": 4, "client_side": 5, "not_in_use": 6}
    for pu in plugin_updates.values():
        pu["plugin_versions"].sort(key=lambda v: [int(n) if n.isdigit() else 0 for n in re.split(r"[.\-]", v)])
    entries = sorted(merged.values(), key=lambda x: (order[x["category"]], rel_order[x["relevance"]], x["component"] or "", min(x["versions"])))
    for x in entries:
        x["first_version"] = min(x["versions"], key=lambda s: tuple(map(int, s.split("."))))

    # The report file: everything that must be read, plus opportunities on things the cluster uses.
    def in_report(x: dict[str, Any]) -> bool:
        if focus is not None:
            return x["relevance"] in ("in_use", "mentions")
        if comparison:
            return x["category"] in MUST_READ or x["category"] == "feature"
        if x["category"] in ("breaking", "deprecation"):
            return True
        if x["category"] in MUST_READ:
            return x["relevance"] in ("in_use", "cluster_wide", "unclassified")
        return x["relevance"] == "in_use"

    impact = [x for x in entries if in_report(x)]
    summary: dict[str, dict[str, int]] = {}
    for x in entries:
        summary.setdefault(x["category"], {}).setdefault(x["relevance"], 0)
        summary[x["category"]][x["relevance"]] += 1

    minor_lines = sorted({r["version"][:2] for r in in_span})
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "generated_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
        "mode": "resource" if focus is not None else "comparison" if comparison else "report",
        "focus": focus,
        "inputs": meta["inputs"],
        "sources": meta["sources"],
        "cluster": {"name": meta["cluster_name"], "version": vstr(current), "version_raw": meta["version_raw"], "enterprise": enterprise},
        "target": {"requested": meta["requested"], "resolved": vstr(target), "release_date": cutoff, "major_upgrade": target[0] > current[0]},
        "span": {
            "releases": [vstr(r["version"]) + (" Enterprise" if r["enterprise_only"] else "") for r in in_span],
            "minor_lines": [f"{a}.{b}" for a, b in minor_lines],
            "minor_lines_crossed": len(minor_lines),
            "excluded_released_after_target": excluded,
            "already_shipped_dropped": already_shipped,
            # Distinct must-read entries dropped: a section can be empty because the current version already has them.
            "already_shipped_must_read": {c: len(shipped_must_read[c]) for c in ("breaking", "deprecation", "security", "change") if c in shipped_must_read},
            "current_released_after_target": bool(cutoff and current_date and current_date > cutoff),
        },
        "docs": docs_links(minor_lines),
        "profile": profile,
        "summary": {"by_category": summary, "plugin_updates": len(plugin_updates), "impact_entries": len(impact), "all_entries": len(entries)},
        "resources": resources,
        "dependency_advisories": {"count": len(advisories), "ids": sorted(advisories)},
        "go_toolchain": sorted(go_versions, key=lambda v: tuple(int(n) for n in v.split(".") if n.isdigit())),
        "plugin_updates": sorted(
            (pu for pu in plugin_updates.values() if focus is None or pu["relevance"] == "in_use"), key=lambda p: (rel_order[p["relevance"]], p["component"])
        ),
        "impact": impact,
        "other_counts_by_component": _other_counts(entries, impact),
    }


def _other_counts(entries: list[dict[str, Any]], impact: list[dict[str, Any]]) -> dict[str, int]:
    ids = {id(x) for x in impact}
    counts: dict[str, int] = {}
    for x in entries:
        if id(x) not in ids:
            counts[x["component"] or "(none)"] = counts.get(x["component"] or "(none)", 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: -kv[1]))


def load_releases(args: argparse.Namespace, current: Version, enterprise: bool) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    sources: dict[str, Any] = {"changelog": [], "enterprise_repo": "not applicable (Community)"}
    releases: list[dict[str, Any]] = []
    if args.changelog:
        for path in args.changelog:
            releases += parse_changelog(Path(path).read_text(), path)
            sources["changelog"].append({"source": path, "status": "read"})
    else:
        for name, floor in CHANGELOG_FILES:
            url = f"{RAW_BASE}/{name}"
            try:
                releases += parse_changelog(fetch_text(url), url)
                sources["changelog"].append({"source": url, "status": "read"})
            except OSError as exc:
                if name == "CHANGELOG.md":
                    fatal(f"cannot download {url} ({type(exc).__name__}). Check network access, or pass --changelog with a local copy.")
                sources["changelog"].append({"source": url, "status": f"unavailable: {type(exc).__name__}"})
            if current >= floor:
                break  # older files cover only versions below the current one
    if enterprise:
        if args.no_enterprise_repo:
            sources["enterprise_repo"] = "skipped (--no-enterprise-repo)"
        else:
            text, status = fetch_enterprise_changelog()
            sources["enterprise_repo"] = status
            if text:
                releases += parse_changelog(text, f"github.com/{ENTERPRISE_REPO}")
    if not releases:
        fatal("no releases parsed from the changelog")
    return releases, sources


def strip_build(raw: str) -> str:
    """`vault version` prints 1.19.5+ent; the build suffix isn't part of the version."""
    return re.sub(r"\+.*$", "", raw.strip())


def resolve_current(raw: str, releases: list[dict[str, Any]], enterprise: bool) -> Version:
    """--current accepts MAJOR.MINOR.PATCH (with any +build suffix), or MAJOR.MINOR (or .x) meaning that line's latest patch."""
    m = TARGET_RE.match(strip_build(raw))
    if not m:
        fatal(f"cannot parse current version {raw!r}; use MAJOR.MINOR or MAJOR.MINOR.PATCH, e.g. 1.21 or 1.19.5")
    if not m[3] or m[3].lower() == "x":
        line = sorted(r["version"] for r in releases if r["version"][:2] == (int(m[1]), int(m[2])) and (enterprise or not r["enterprise_only"]))
        if not line:
            fatal(f"no {m[1]}.{m[2]}.x release in the Vault changelog{'' if enterprise else ' (Community releases)'}")
        return line[-1]
    v = (int(m[1]), int(m[2]), int(m[3]))
    if v not in {r["version"] for r in releases}:
        warn(f"warning: {vstr(v)} is not in the Vault changelog; comparing from it anyway")
    return v


def write_outputs(doc: dict[str, Any], out_dir: Path, stem: str) -> None:
    if not out_dir.exists():
        out_dir.mkdir(parents=True)
        (out_dir / ".gitignore").write_text("*\n")
    for ext, body in (("json", json.dumps(doc, indent=2) + "\n"), ("md", render_markdown(doc))):
        path = out_dir / f"{stem}.{ext}"
        path.write_text(body)
        path.chmod(0o600)
        print(path)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--target", required=True, help="target Vault version: MAJOR.MINOR (latest patch) or MAJOR.MINOR.PATCH")
    start = p.add_mutually_exclusive_group(required=True)
    start.add_argument("--current", help="current version (resource mode with --resource, comparison mode without)")
    start.add_argument("--report", help="vault-tools namespace audit report (.md): current version, edition and inventory come from it")
    p.add_argument("--resource", action="append", default=[], help=f"focus on one resource (repeatable): {RESOURCE_HELP}")
    p.add_argument("--edition", choices=["enterprise", "community"], help="edition for --current (default enterprise: all entries, Enterprise-only ones marked)")
    p.add_argument("--output-dir", help="where to write the result (default $VAULT_UPGRADE_ANALYZER_DIR or .tmp/vault-upgrade-analyzer)")
    p.add_argument("--changelog", action="append", default=[], help="local CHANGELOG file(s) to use instead of downloading (repeatable)")
    p.add_argument("--no-enterprise-repo", action="store_true", help="never try the private vault-enterprise repo")
    args = p.parse_args()
    out_dir = Path(args.output_dir or os.environ.get("VAULT_UPGRADE_ANALYZER_DIR") or ".tmp/vault-upgrade-analyzer")
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    inputs: dict[str, Any] = {}
    cluster_name, prefix = None, "vault"

    if args.current:
        profile, focus, keywords = parse_resources(args.resource) if args.resource else (unknown_inventory(), None, None)
        if "+ent" in args.current and args.edition == "community":
            warn(f"warning: {args.current} is an Enterprise build but --edition community was given; using community")
        enterprise = args.edition != "community"
        releases, sources = load_releases(args, _version_floor(args.current), enterprise)
        current = resolve_current(args.current, releases, enterprise)
        version_raw = args.current
    else:
        path = Path(args.report)
        if not path.is_file():
            fatal(f"report {path} not found")
        report = parse_audit_report(path)
        version_raw, current, enterprise = report["version_raw"], report["version"], report["enterprise"]
        if args.edition:
            warn(f"warning: --edition is ignored with --report; the report says {'Enterprise' if enterprise else 'Community'}")
        cluster_name = report["cluster_name"]
        prefix = re.sub(r"[^A-Za-z0-9_.-]+", "-", cluster_name or "vault")
        inputs = {"report": str(path), "report_generated": report["generated"], "report_age_hours": report["age_hours"], "collected_by": report["tool"]}
        if args.resource:
            # Resource focus on a reported cluster: version and edition come from the report.
            profile, focus, keywords = parse_resources(args.resource)
        else:
            p = report["profile"]
            if not (p["auth_types"] or p["secrets_types"]):
                fatal(
                    f"{path.name} has no mount inventory: the node may have been sealed, uninitialised or a DR secondary when it was audited. "
                    "Audit the primary or an unsealed active node, or use resource mode (--resource)."
                )
            profile, focus, keywords = p, None, None
        releases, sources = load_releases(args, current, enterprise)

    target = resolve_target(args.target, releases, enterprise)
    if target <= current:
        fatal(f"target {vstr(target)} is not newer than the current {vstr(current)}")
    meta = {"inputs": inputs, "sources": sources, "cluster_name": cluster_name, "version_raw": version_raw, "requested": args.target}
    doc = build_document(current, target, enterprise, releases, profile, meta, focus, keywords)
    if args.changelog:
        doc["plugin_changelogs_skipped"] = "plugin changelogs not checked: --changelog (offline) was used"
    elif doc["mode"] == "comparison":
        doc["plugin_changelogs_skipped"] = "plugin changelogs not checked: comparison mode names no resource; re-run with --resource for one plugin's changelog"
    else:
        # Plugin changelogs: always for a resource; for a report, the plugin-backed types the cluster runs (capped).
        wanted = [pu for pu in doc["plugin_updates"] if pu.get("repo") and pu["relevance"] == "in_use"]
        doc["plugin_changelogs"] = [plugin_changelog(pu, releases, current) for pu in wanted[: None if focus is not None else 10]]
        if focus is not None:
            # A deterministic API docs diff, so the agent doesn't fetch and compare the pages itself.
            doc["api_diffs"] = [api_diff(r, current, target) for r in focus]
    slug = "" if focus is None else "-" + "+".join(re.sub(r"[^a-z0-9]+", "-", f) for f in focus)
    write_outputs(doc, out_dir, f"{prefix}-upgrade-analyzer{slug}-{vstr(current)}-to-{vstr(target)}-{stamp}")


def _version_floor(raw: str) -> Version:
    m = TARGET_RE.match(strip_build(raw))
    return (int(m[1]), int(m[2]), 0) if m else (0, 0, 0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
