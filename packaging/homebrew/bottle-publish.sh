#!/bin/bash
# Merge the per-arch bottles built by bottle-build.sh into the tap's comrade
# formula, upload the bottle tarballs to the tag's GitHub release, and push the
# tap, so `brew install comrade` fetches a prebuilt binary for either macOS arch.
# The bottle tarballs and JSONs from every arch are expected under ./bottles.
#
# Environment: VERSION, TAP_TOKEN (write access to the tap), GH_TOKEN.
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

log "Upload the bottles to the release"
gh release create "$TAG" \
  --title "comrade $V" \
  --notes "comrade $V. See the apt, winget and Homebrew instructions in the README." \
  2>/dev/null || true
# `brew bottle` writes the local file with a doubled dash (comrade--<version>),
# but Homebrew fetches the canonical single-dashed name (comrade-<version>) at
# install time. Rename so `brew install` resolves them on the release. --merge
# below reads the JSONs, not the tarballs, so it is unaffected.
for f in bottles/*--*.bottle.tar.gz; do
  [ -e "$f" ] && mv "$f" "$(echo "$f" | sed 's/--/-/')"
done
gh release upload "$TAG" bottles/*.bottle.tar.gz --clobber

# --merge folds every arch's JSON into one bottle block (each JSON already
# carries its own os/arch tag and the release root_url set at build time).
log "Merge all arches into the formula and push the tap"
brew bottle --merge --write --no-commit bottles/*.bottle.json
cd "$TAPS"
git config user.name 'github-actions[bot]'
git config user.email 'github-actions[bot]@users.noreply.github.com'
git add Formula/comrade.rb Formula/libjuice.rb Formula/kcp.rb Formula/libdht.rb
git commit -m "comrade $V: bottles and formula update"
git push
