#!/bin/bash
# Build a Homebrew bottle for comrade for ONE architecture -- the one this macOS
# runner is -- and leave the .bottle.tar.gz and .bottle.json in the working
# directory for the workflow to upload as an artifact. A macOS bottle must be
# built natively per arch, so the release runs this on an Intel and an
# Apple-Silicon runner; bottle-publish.sh then merges both arches into the tap.
#
# No tap token is needed here: this only builds and bottles, using a throwaway
# local tap. bottle-publish.sh does the pushing.
#
# Environment: VERSION (release version, e.g. 0.1.0).
set -euo pipefail

V="$VERSION"
TAG="v$V"
REPO="dangowrt/comrade"
TAP="dangowrt/comrade"          # Homebrew tap name (homebrew- stripped)
ROOT_URL="https://github.com/$REPO/releases/download/$TAG"
GIT_URL="https://github.com/$REPO.git"
REVISION="$(git rev-parse HEAD)"

log() { printf '\n=== %s ===\n' "$*"; }
echo "brew: $(brew --version | head -1);  macOS: $(sw_vers -productVersion);  arch: $(uname -m)"

log "Set up a throwaway local tap with the versioned formula"
TAPS="$(brew --repository)/Library/Taps/dangowrt/homebrew-comrade"
rm -rf "$TAPS"
mkdir -p "$TAPS/Formula"
cp packaging/homebrew/libjuice.rb packaging/homebrew/kcp.rb \
   packaging/homebrew/libdht.rb "$TAPS/Formula/"
# Build from the git tag at its exact revision so Homebrew clones with the
# always-online-stun submodule (GitHub's tag tarball omits submodule content);
# the submodule is the single source of truth for the pinned STUN list.
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
( cd "$TAPS" && git init -q && git config user.email ci@local && git config user.name ci \
    && git add -A && git commit -qm init )

# Homebrew 6.0+ refuses formulae from an untrusted tap; older brew lacks the
# command, so ignore its absence.
log "Trust the tap"
brew trust "$TAP" 2>/dev/null || true

# A runner with comrade (or a dep) already installed from another tap would make
# brew refuse the same-named formula.
log "Remove any pre-existing comrade and deps"
for f in comrade libjuice kcp libdht; do
  brew uninstall --ignore-dependencies --force "$f" 2>/dev/null || true
done

# The deps have no bottles and --build-bottle will not build them from source,
# so install them first, then build comrade for bottling.
log "Install the source-built dependencies, then bottle-build comrade"
brew install "${TAP}/libjuice" "${TAP}/kcp" "${TAP}/libdht"
brew install --build-bottle "${TAP}/comrade"

log "Produce the bottle and its JSON"
rm -f ./*.bottle.tar.gz ./*.bottle.json
brew bottle --json --no-rebuild --root-url="$ROOT_URL" "${TAP}/comrade"
ls -la ./*.bottle.*
