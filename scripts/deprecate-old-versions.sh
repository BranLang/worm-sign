#!/usr/bin/env bash
# Deprecate old published versions of worm-sign on npm.
#
# A scanner that misses an active campaign is worse than no scanner — it
# gives a false sense of safety. The releases below either pre-date the
# safe-static-analysis migration (Arborist) or miss campaign coverage
# they should have detected.
#
# Usage:
#   npm login                       # required, must be a maintainer
#   ./scripts/deprecate-old-versions.sh                # deprecate 1.x-3.x + 4.0.0 (default)
#   ./scripts/deprecate-old-versions.sh --include-4.1  # also deprecate 4.1.0 (run AFTER 4.2.0 ships)
#
# Safe to re-run: `npm deprecate` is idempotent.
set -euo pipefail

PKG="worm-sign"
INCLUDE_410="${1:-}"

# Ensure caller is authenticated as a maintainer.
if ! npm whoami >/dev/null 2>&1; then
  echo "ERROR: not logged into npm. Run 'npm login' first." >&2
  exit 1
fi
echo "Authenticated as: $(npm whoami)"
echo

# Confirm before mutating the registry.
read -r -p "Deprecate old ${PKG} versions on npm? [y/N] " ans
case "${ans}" in
  y|Y|yes) ;;
  *) echo "Aborted."; exit 0 ;;
esac

run() {
  echo "→ npm deprecate '$1' '$2'"
  npm deprecate "$1" "$2"
}

# 1.x — initial releases. No Arborist (legacy parsers), no campaign coverage,
# no SARIF, no heuristic layer. Functionally unsafe to rely on.
run "${PKG}@\"<2.0.0\"" \
  "worm-sign 1.x is no longer maintained — predates safe-static-analysis (Arborist) and has zero active-campaign coverage. Upgrade: npm i -g worm-sign@latest"

# 2.x — pre-Arborist (2.0.x – 2.3.x). 2.2.0 added Shai-Hulud 2.0 names but
# scanning could still trigger lifecycle scripts in some flows.
run "${PKG}@\"<3.0.0 >=2.0.0\"" \
  "worm-sign 2.x is no longer maintained — uses legacy lockfile parsers and predates Arborist-based safe scanning. Upgrade: npm i -g worm-sign@latest"

# 3.x — Arborist-based, but pre-Axios and pre-TanStack. A scanner that
# can't see two of the three named worms is a liability.
run "${PKG}@\"<4.0.0 >=3.0.0\"" \
  "worm-sign 3.x is no longer maintained — missing Axios (Mar 2026, CVE-pending) and TanStack wave 4 (May 2026, CVE-2026-45321) coverage. Upgrade: npm i -g worm-sign@latest"

# 4.0.0 — Axios coverage but no TanStack wave 4. Misses GHSA-g7cv-rxg3-hmpx.
run "${PKG}@4.0.0" \
  "worm-sign 4.0.0 missing TanStack wave 4 coverage (GHSA-g7cv-rxg3-hmpx, May 2026). Upgrade to >=4.2.0."

# 4.1.0 had a CI-gating bug: critical heuristic findings could produce exit 0
# when no package-name match existed (zero-day worm propagation scenario).
# Deprecate only after 4.2.0 ships, to avoid leaving users on a deprecated
# latest.
if [[ "${INCLUDE_410}" == "--include-4.1" ]]; then
  run "${PKG}@4.1.0" \
    "worm-sign 4.1.0 had a CLI exit-code bug: critical heuristic findings could exit 0 without a package-name match (zero-day worm scenario). Upgrade to >=4.2.0."
fi

echo
echo "Done. Verify with: npm view ${PKG} versions --json && npm view ${PKG}@<v> deprecated"
