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
# The commit and the PR description both quote a changelog built from this
# repo's own `git log`, not from GitHub Release notes: the release notes
# turned out to be boilerplate repeated almost verbatim release after
# release, not an actual changelog, and are not even a reliable source --
# several comrade releases have shipped a real tag with no Release object
# at all (a release job that failed after tagging). Tags are the ground
# truth instead. The changelog covers every commit since whatever version
# openwrt/packages currently has, not just v$VERSION: a bump PR sitting
# open across several comrade releases -- or a reviewer taking a while to
# get to it -- means that can be several releases behind v$VERSION, and
# nothing in between should go missing. That "currently has" version is
# read straight out of upstream's own net/comrade/Makefile, not tracked
# separately here.
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
# below (PR lookup, PR create/edit) tolerate it fine, since it just rides
# along inside an Authorization header; embedding the raw token in a URL's
# userinfo further down does not, and libcurl rejects any whitespace there
# outright ("URL rejected: Malformed input to a URL function"), not only an
# embedded newline. Strip all whitespace, not just \n\r.
OPENWRT_PACKAGES_TOKEN="$(printf '%s' "$OPENWRT_PACKAGES_TOKEN" | tr -d '[:space:]')"

V="$VERSION"
NAME="Daniel Golle"
EMAIL="daniel@makrotopia.org"
UPSTREAM_REPO="openwrt/packages"
FORK_REPO="dangowrt/packages"
PKG_DIR="net/comrade"
BRANCH="comrade-update"
# This checkout of comrade itself, captured before the fork clone below cds
# elsewhere -- the changelog is built from this repo's own tags and log, not
# from anything fetched over the network.
COMRADE_DIR="$PWD"
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

log "Walk this repo's own tags from v$OLD_V (exclusive) to v$V (inclusive)"
# version:refname is git's numeric tag sort (vN.N.N in numeric rather than
# lexical order), so this list is oldest first regardless of what order the
# tags were actually pushed in.
mapfile -t ALL_TAGS < <(git -C "$COMRADE_DIR" tag --sort=version:refname)
STEP_TAGS=()
collecting=0
for t in "${ALL_TAGS[@]}"; do
  [ "$collecting" -eq 1 ] && STEP_TAGS+=("$t")
  [ "$t" = "v$OLD_V" ] && collecting=1
  [ "$t" = "v$V" ] && break
done
# v$OLD_V is not a tag this repo has (Makefile carries a version this repo
# never released, or the tag was deleted) -- fall back to the single release
# being bumped to, same as when there is nothing to catch up on at all.
[ "${#STEP_TAGS[@]}" -eq 0 ] && STEP_TAGS=("v$V")

log "Build the changelog for the commit and the PR description"
# Each step's commits become a bullet list of `owner/repo@hash` references,
# GitHub's own autolink syntax for a commit in another repository -- left
# unfenced (no code block) so GitHub actually renders the links instead of
# showing literal text. --reverse so commits within a step read oldest
# first, same direction as the steps themselves (v$OLD_V's successor first,
# v$V last): one consistent chronological read top to bottom, not steps
# going forward in time while each step's own commits count backward.
CHANGELOG=""
prev="v$OLD_V"
for t in "${STEP_TAGS[@]}"; do
  if git -C "$COMRADE_DIR" rev-parse -q --verify "refs/tags/$prev" >/dev/null; then
    step="$(git -C "$COMRADE_DIR" log --oneline --reverse "$prev..$t" \
      | sed -E 's#^([0-9a-f]+) (.*)$#- dangowrt/comrade@\1 \2#')"
  else
    step="(v$OLD_V is not a tag here; showing the last 20 commits up to $t)

$(git -C "$COMRADE_DIR" log --oneline --reverse -n 20 "$t" \
      | sed -E 's#^([0-9a-f]+) (.*)$#- dangowrt/comrade@\1 \2#')"
  fi
  CHANGELOG="${CHANGELOG:+$CHANGELOG$'\n\n'}### $t

$step"
  prev="$t"
done

log "Commit and force-push over whatever was on $BRANCH before"
git add "$PKG_DIR/Makefile"
git commit --quiet --signoff -m "$TITLE" -m "$CHANGELOG"
git push --quiet --force-with-lease origin "$BRANCH:$BRANCH"

log "Write the PR title and description, openwrt/packages' own template"
BODY="$(mktemp)"
cat > "$BODY" <<EOF
## 📦 Package Details

**Maintainer:** @dangowrt

**Description:**
Update net/comrade to $V.

$CHANGELOG

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
