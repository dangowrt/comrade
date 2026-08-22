#!/bin/bash
# Merge the per-arch bottles built by bottle-build.sh into the tap's comrade
# formula AND its three dependency formulae (libjuice, kcp, libdht), then push
# the tap, so `brew install comrade` fetches a complete set of prebuilt
# binaries for either macOS arch with no build toolchain required. The bottle
# JSONs from every arch and every formula are expected under ./bottles;
# --merge reads those, not the tarballs, and groups them by the formula name
# each JSON carries, so one invocation updates all four formula files.
#
# The tarballs themselves are already on the tag's GitHub release, put there by
# the release workflow's `release` job together with every other release asset,
# so nothing here touches the release. Run this only after that job, or the
# formula would name bottles that cannot be downloaded yet.
#
# Environment: VERSION, TAP_TOKEN (write access to the tap).
set -euo pipefail

V="$VERSION"
TAG="v$V"
REPO="dangowrt/comrade"
TAP_REPO="dangowrt/homebrew-comrade"   # the tap's GitHub repository
TAP="dangowrt/comrade"                  # Homebrew tap name (homebrew- stripped)
GIT_URL="https://github.com/$REPO.git"
REVISION="$(git rev-parse HEAD)"

log() { printf '\n=== %s ===\n' "$*"; }

log "Clone the tap and inject the versioned formula"
TAPS="$(brew --repository)/Library/Taps/dangowrt/homebrew-comrade"
rm -rf "$TAPS"
mkdir -p "$(dirname "$TAPS")"
git clone "https://x-access-token:${TAP_TOKEN}@github.com/${TAP_REPO}.git" "$TAPS"
mkdir -p "$TAPS/Formula"
cp packaging/homebrew/libjuice.rb packaging/homebrew/kcp.rb \
   packaging/homebrew/libdht.rb "$TAPS/Formula/"
# Same git tag+revision source as bottle-build.sh, so Homebrew clones the
# always-online-stun submodule; the submodule is the single source of truth.
awk -v url="$GIT_URL" -v tag="$TAG" -v rev="$REVISION" '
  /^[[:space:]]*homepage / {
    print
    print "  url \"" url "\","
    print "      tag:      \"" tag "\","
    print "      revision: \"" rev "\""
    next
  }
  { print }
' packaging/homebrew/comrade.rb > "$TAPS/Formula/comrade.rb"
brew trust "$TAP" 2>/dev/null || true

# --merge folds every arch's JSON into one bottle block per formula (each JSON
# already carries its own formula name, os/arch tag and the release root_url
# set at build time), so this one call updates comrade.rb, libjuice.rb, kcp.rb
# and libdht.rb together.
log "Merge all arches and formulae, and push the tap"
brew bottle --merge --write --no-commit bottles/*.bottle.json
cd "$TAPS"
git config user.name 'github-actions[bot]'
git config user.email 'github-actions[bot]@users.noreply.github.com'
git add Formula/comrade.rb Formula/libjuice.rb Formula/kcp.rb Formula/libdht.rb
git commit -m "comrade $V: bottles and formula update"
git push
