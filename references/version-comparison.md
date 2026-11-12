# Comparison mode

You have two versions and know nothing about what's deployed. Never assume a component is in use:
- An `if_used` entry is **Potential**, with the component as the condition ("applies if you use the PKI secrets engine").
- A `cluster_wide` entry is usually **Confirmed**.

The capture, scope, applicability and severity rules are in SKILL.md step 4.

## 1. From the summary header

- the minor lines crossed (you need the docs for each one)
- whether the span crosses a major version
- the excluded later releases (a known issue fixed in one of them is a reason to recommend a later patch)

Must-read entries are grouped by component. The changelog files some breaking changes under `CHANGES:`, so the important-changes pages are the main source for the breaking-change list.

## 2. Fetch

The order follows [sources.md](sources.md). Comparison mode covers every component, so the fetches ask for all entries. Ask only for the capture fields, not the prose around them.

1. **Change tracker**: one fetch for every line from 1.16 on. Ask for the breaking changes, new behaviour and known issues in the span.
2. **Important changes** (1.16+) or **upgrade guides** (1.15 and older), for each line in "Docs to read": prerequisites and required actions.
3. **Deprecation notices**: entries within the span only.
4. **Release notes** for the target line: the deprecation and EOL table, plus the "Enterprise" label for any finding whose edition the changelog and docs disagree on, or don't give.
5. **Upgrade guides** (general, replicated, HA): only if the span needs an intermediate version or a special order.

Plugin changelogs aren't fetched in comparison mode. Offer a resource-mode run for a plugin that matters.

## 3. Check before writing

- Every line in the span was reviewed, or is listed under "Not covered".
- No finding is already in the source version, and none comes from a release newer than the target.
- Security fixes say whether the source was affected.
- The gaps are stated: the Enterprise repo, plugin changelogs, and any pages that couldn't be fetched.
