#!/bin/bash
# Bump net/comrade/Makefile in the dangowrt fork of openwrt/packages to the
# tagged release, then open the version-bump PR against openwrt/packages -- or,
# if an earlier release's bump PR is still open and unmerged, adopt it: force-
# push the new commit onto that same PR's branch and replace its title and
# description, rather than leaving it stale and opening a second PR next to
# it. The branch is always the fixed name below, a singleton by construction
# (there is only ever at most one comrade bump PR open at a time), rather than
# a version-suffixed name that would suggest otherwise. When there is no open
# PR left to adopt -- the last one merged or was closed -- the same-named
# branch from that PR is deleted from the fork before being recreated fresh,
# so a merged bump never lingers as a dangling ref; the branch content itself
# is likewise never a merge/rebase of what used to be there, always a fresh
# commit off upstream's current master.
#
# PKG_HASH is taken from GitHub's own codeload tarball for v$VERSION, not from
# anything this repo builds, so this only needs the tag to exist -- it does
# not wait on the release job.
#
# The PR description quotes release notes, but not just this release's: a
# bump PR sitting open across several comrade releases -- or a reviewer
# taking a while to get to it -- means the version openwrt/packages
# currently has can be several releases behind v$VERSION, so the notes for
# everything in between belong in the description too, not just the last
# one. That "currently has" version is read straight out of upstream's own
# net/comrade/Makefile, not tracked separately here.
#
# Environment: VERSION, OPENWRT_PACKAGES_TOKEN.
#
# OPENWRT_PACKAGES_TOKEN must be a *classic* PAT (public_repo scope) for the
# dangowrt account, not a fine-grained one: fine-grained PATs are scoped to
# repos their owner explicitly grants them, and both the PR lookup below and
# opening/editing a PR land on openwrt/packages' own endpoints -- a repo
# dangowrt does not own -- which fine-grained tokens reject with 403 even
# when the head branch sits in a fork the token can otherwise push to freely.
# Classic PATs are not repo-scoped that way, so they are the only kind that
# actually works here.
#
# No commit signing key: openwrt/packages' CONTRIBUTING.md only requires a
# Signed-off-by trailer with a real, non-noreply name and email
# (check_signoff, check_noreply_email, require_linked_github_account below),
# not a cryptographically signed commit -- `git commit --signoff` covers it.
set -euo pipefail

# Secrets pasted into GitHub's UI routinely pick up stray whitespace -- a
# trailing newline, a leading or trailing space -- invisible in the guard
# step's -z check (the string is non-empty either way). gh's own API calls
# below (PR lookup, release notes, PR create/edit) tolerate it fine, since it
# just rides along inside an Authorization header; embedding the raw token in
# a URL's userinfo further down does not, and libcurl rejects any whitespace
# there outright ("URL rejected: Malformed input to a URL function"), not
# only an embedded newline. Strip all whitespace, not just \n\r.
OPENWRT_PACKAGES_TOKEN="$(printf '%s' "$OPENWRT_PACKAGES_TOKEN" | tr -d '[:space:]')"

V="$VERSION"
NAME="Daniel Golle"
EMAIL="daniel@makrotopia.org"
UPSTREAM_REPO="openwrt/packages"
FORK_REPO="dangowrt/packages"
PKG_DIR="net/comrade"
BRANCH="comrade-update"
# The title stays version-specific even though the branch name is fixed:
# openwrt/packages' formalities bot flags generic subjects
# (warn_generic_subjects), and "comrade-update" with no version in it reads
# as exactly that in the PR list.
TITLE="comrade: update to $V"

log() { printf '\n=== %s ===\n' "$*"; }

# Runner-local cleanup only -- the clone below is a fresh tmpdir every run,
# never cached across runs, so there is nothing "local" to leak between runs
# regardless; this just tidies up the one run currently in progress.
cleanup() { rm -rf "${WORK:-}"; rm -f "${BODY:-}"; }
trap cleanup EXIT

# See the classic-vs-fine-grained note above -- needed before the PR lookup
# below, not just for the push/create/edit calls further down.
export GH_TOKEN="$OPENWRT_PACKAGES_TOKEN"

log "Look for a still-open comrade bump PR to adopt"
ADOPT_PR="$(gh pr list --repo "$UPSTREAM_REPO" --author dangowrt --state open \
  --limit 100 --json number,headRefName \
  --jq "[.[] | select(.headRefName == \"$BRANCH\")][0].number // empty")"

log "Compute the tarball hash codeload will serve for v$V"
HASH="$(curl -fsSL "https://codeload.github.com/dangowrt/comrade/tar.gz/v$V" | sha256sum | cut -d' ' -f1)"

log "Clone the fork and rebuild $BRANCH fresh off upstream's current master"
WORK="$(mktemp -d)"
git clone --quiet "https://x-access-token:${OPENWRT_PACKAGES_TOKEN}@github.com/${FORK_REPO}.git" "$WORK"
cd "$WORK"
git remote add upstream "https://github.com/${UPSTREAM_REPO}.git"
git fetch --quiet upstream master
if [ -z "$ADOPT_PR" ]; then
  # Nothing open to adopt, so any $BRANCH still on the fork is a leftover
  # from a PR that already merged or got closed -- drop it rather than build
  # the new commit on top of stale history.
  git push --quiet origin --delete "$BRANCH" 2>/dev/null || true
fi
git checkout --quiet -B "$BRANCH" upstream/master

log "Read the version net/comrade currently references upstream"
OLD_V="$(sed -n 's/^PKG_VERSION:=//p' "$PKG_DIR/Makefile")"

log "Bump PKG_VERSION, reset PKG_RELEASE, refresh PKG_HASH"
sed -i \
  -e "s/^PKG_VERSION:=.*/PKG_VERSION:=$V/" \
  -e "s/^PKG_RELEASE:=.*/PKG_RELEASE:=1/" \
  -e "s/^PKG_HASH:=.*/PKG_HASH:=$HASH/" \
  "$PKG_DIR/Makefile"
grep -q "^PKG_VERSION:=$V$" "$PKG_DIR/Makefile"
grep -q "^PKG_HASH:=$HASH$" "$PKG_DIR/Makefile"

git config user.name "$NAME"
git config user.email "$EMAIL"

log "Pull this release's notes for the commit"
# Left unwrapped: the GitHub release body is a markdown bullet list, and
# blindly re-wrapping it (fmt et al.) merges the bullets into one paragraph.
NOTES="$(gh release view "v$V" --repo dangowrt/comrade --json body --jq .body)"

log "Pull every release's notes since v$OLD_V for the PR description"
# openwrt/packages may be several comrade releases behind v$V by the time
# this runs (a bump PR left open a while, or several releases in a row with
# nothing to adopt), so the description should not silently drop what
# changed in between. Fall back to just this release's notes if v$OLD_V
# does not resolve to a real release (deleted, or the Makefile did not
# actually carry a version) or if there is nothing to catch up on.
ALL_RELEASES="$(gh release list --repo dangowrt/comrade --json tagName,createdAt --limit 1000)"
OLD_DATE="$(jq -r --arg t "v$OLD_V" '[.[] | select(.tagName == $t)][0].createdAt // empty' <<<"$ALL_RELEASES")"
NEW_DATE="$(jq -r --arg t "v$V" '[.[] | select(.tagName == $t)][0].createdAt // empty' <<<"$ALL_RELEASES")"
if [ -n "$OLD_DATE" ] && [ -n "$NEW_DATE" ] && [ "$OLD_V" != "$V" ]; then
  NOTE_TAGS="$(jq -r --arg lo "$OLD_DATE" --arg hi "$NEW_DATE" \
    '[.[] | select(.createdAt > $lo and .createdAt <= $hi)] | sort_by(.createdAt) | .[].tagName' \
    <<<"$ALL_RELEASES")"
else
  NOTE_TAGS="v$V"
fi
ALL_NOTES=""
while IFS= read -r tag; do
  [ -n "$tag" ] || continue
  tag_notes="$(gh release view "$tag" --repo dangowrt/comrade --json body --jq .body)"
  ALL_NOTES="${ALL_NOTES:+$ALL_NOTES$'\n\n'}### $tag

$tag_notes"
done <<<"$NOTE_TAGS"

log "Commit and force-push over whatever was on $BRANCH before"
git add "$PKG_DIR/Makefile"
git commit --quiet --signoff -m "$TITLE" -m "$NOTES"
git push --quiet --force-with-lease origin "$BRANCH:$BRANCH"

log "Write the PR title and description, openwrt/packages' own template"
BODY="$(mktemp)"
cat > "$BODY" <<EOF
## 📦 Package Details

**Maintainer:** @dangowrt

**Description:**
Update net/comrade to $V.

$ALL_NOTES

---

## 🧪 Run Testing Details

- **OpenWrt Version:** -
- **OpenWrt Target/Subtarget:** -
- **OpenWrt Device:** -

---

## ✅ Formalities

- [x] I have reviewed the [CONTRIBUTING.md](https://github.com/openwrt/packages/blob/master/CONTRIBUTING.md) file for detailed contributing guidelines.
EOF

if [ -n "$ADOPT_PR" ]; then
  log "Replacing PR #$ADOPT_PR's title and description"
  gh pr edit "$ADOPT_PR" --repo "$UPSTREAM_REPO" --title "$TITLE" --body-file "$BODY"
else
  log "Opening the PR"
  gh pr create --repo "$UPSTREAM_REPO" --base master --head "dangowrt:$BRANCH" \
    --title "$TITLE" --body-file "$BODY"
fi
