#!/bin/bash
# Bump net/comrade/Makefile in the dangowrt fork of openwrt/packages to the
# tagged release, then open the version-bump PR against openwrt/packages -- or,
# if an earlier release's bump PR is still open and unmerged, adopt it: check
# out that PR's branch, content included, squash the bump into its single
# commit and force-push, replacing the PR's title and description, rather than
# leaving it stale and opening a second PR next to it. Adoption takes the
# branch, not just the number: an open PR may carry more than the previous
# bump (a new sub-package, a test), and a branch rebuilt from scratch would
# silently drop all of that. The adopted branch is rebased onto upstream's
# current master where that is conflict-free, and left on its old base --
# still correct, just older -- where it is not. The branch is always the fixed
# name below, a singleton by construction (there is only ever at most one
# comrade bump PR open at a time), rather than a version-suffixed name that
# would suggest otherwise. When there is no open PR left to adopt -- the last
# one merged or was closed -- the same-named branch from that PR is deleted
# from the fork before being recreated fresh off upstream's current master, so
# a merged bump never lingers as a dangling ref.
#
# PKG_HASH is taken from the release's own source tarball for v$VERSION, not
# from a GitHub-generated archive (see the note further down) or anything
# this repo builds itself -- but that tarball is minted and attached by the
# release job, so this does need to wait on it, unlike PKG_VERSION/PKG_RELEASE
# which only need the tag to exist.
#
# The PR description quotes a changelog built from this repo's own
# `git log`, not from GitHub Release notes: the release notes turned out
# to be boilerplate repeated almost verbatim release after release, not
# an actual changelog, and are not even a reliable source -- several
# comrade releases have shipped a real tag with no Release object at all
# (a release job that failed after tagging). Tags are the ground truth
# instead. The changelog covers every commit since whatever version
# openwrt/packages currently has, not just v$VERSION: a bump PR sitting
# open across several comrade releases -- or a reviewer taking a while to
# get to it -- means that can be several releases behind v$VERSION, and
# nothing in between should go missing. That "currently has" version is
# read straight out of upstream's own net/comrade/Makefile, not tracked
# separately here.
#
# The commit itself carries only a terse compare-URL reference, not the
# changelog: openwrt/packages' own commit convention is short, and a
# multi-release changelog bloats the commit body for no reader who isn't
# already looking at the PR description right above it.
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
# actually works here. The PR create/edit calls further down go through the
# plain REST endpoints (gh api), not gh's PR porcelain: `gh pr edit` fronts
# a GraphQL query whose review/team fields want read:org on the openwrt
# organisation, which is more than this token has or needs.
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

log "Compute the hash of the release's own source tarball for v$V"
# Not codeload: GitHub does not guarantee the bytes of an auto-generated
# "Source code (tar.gz)" download stay stable (they changed the archive
# compression once already, and only commit to a renewable minimum-notice
# window before doing so again -- see
# https://github.blog/changelog/2023-01-30-git-archive-checksums-may-change/).
# The release job mints its own tarball and attaches it as a release asset
# instead, which immutability actually does freeze.
HASH="$(curl -fsSL "https://github.com/dangowrt/comrade/releases/download/v$V/comrade-$V.tar.gz" | sha256sum | cut -d' ' -f1)"

log "Clone the fork"
WORK="$(mktemp -d)"
git clone --quiet "https://x-access-token:${OPENWRT_PACKAGES_TOKEN}@github.com/${FORK_REPO}.git" "$WORK"
cd "$WORK"
git config user.name "$NAME"
git config user.email "$EMAIL"
git remote add upstream "https://github.com/${UPSTREAM_REPO}.git"
git fetch --quiet upstream master

if [ -n "$ADOPT_PR" ]; then
  # The PR's branch carries its content, which may be more than the previous
  # bump -- a new sub-package, a test -- so the bump lands on that branch,
  # squashed into its single commit further down, never on a fresh branch
  # that would silently drop the rest. Keep it current with upstream where
  # that is conflict-free; a conflict leaves the branch on its old base for
  # a human to sort out rather than failing the bump over it.
  log "Adopt PR #$ADOPT_PR's branch, content included"
  git checkout --quiet "$BRANCH"
  if ! git rebase --quiet upstream/master; then
    git rebase --abort
    log "Rebase onto upstream/master conflicts -- keeping the branch's base"
  fi
else
  # Nothing open to adopt, so any $BRANCH still on the fork is a leftover
  # from a PR that already merged or got closed -- drop it rather than build
  # the new commit on top of stale history.
  log "No open PR -- rebuild $BRANCH fresh off upstream's current master"
  git push --quiet origin --delete "$BRANCH" 2>/dev/null || true
  git checkout --quiet -B "$BRANCH" upstream/master
fi

log "Read the version net/comrade currently references upstream"
# From upstream's master, not the checkout: an adopted branch already carries
# the previous bump, and the changelog must still cover everything upstream
# has not merged yet.
OLD_V="$(git show upstream/master:"$PKG_DIR/Makefile" | sed -n 's/^PKG_VERSION:=//p')"

log "Bump PKG_VERSION, reset PKG_RELEASE, point PKG_SOURCE_URL at the release, refresh PKG_HASH"
# PKG_SOURCE_URL is rewritten unconditionally, not left alone if already
# correct: a Makefile still pinned to the old codeload URL from before this
# script minted release-tarball assets gets migrated the moment it is next
# bumped, rather than needing a human to notice and fix it by hand.
sed -i \
  -e "s/^PKG_VERSION:=.*/PKG_VERSION:=$V/" \
  -e "s/^PKG_RELEASE:=.*/PKG_RELEASE:=1/" \
  -e "s|^PKG_SOURCE_URL:=.*|PKG_SOURCE_URL:=https://github.com/dangowrt/comrade/releases/download/v\$(PKG_VERSION)|" \
  -e "s/^PKG_HASH:=.*/PKG_HASH:=$HASH/" \
  "$PKG_DIR/Makefile"
grep -q "^PKG_VERSION:=$V$" "$PKG_DIR/Makefile"
grep -q '^PKG_SOURCE_URL:=https://github.com/dangowrt/comrade/releases/download/v\$(PKG_VERSION)$' "$PKG_DIR/Makefile"
grep -q "^PKG_HASH:=$HASH$" "$PKG_DIR/Makefile"

# The release tarball carries the STUN submodule as an empty directory (git
# archive does not recurse into submodules), so net/comrade downloads the
# pinned list separately (Download/stunlist) and installs it before
# configure. Keep that pin in step with the submodule commit the tag
# actually references -- readable straight off the tag's tree, no submodule
# checkout needed -- and hash the very file OpenWrt will fetch.
# A Makefile without the machinery has no pin to keep in step, and the bump
# must not fail over its absence.
if grep -q '^STUN_LIST_VERSION:=' "$PKG_DIR/Makefile"; then
  log "Read the STUN list pin the v$V tag references and hash that list"
  STUN_REV="$(git -C "$COMRADE_DIR" ls-tree "v$V" deps/always-online-stun | awk '{print $3}')"
  [ -n "$STUN_REV" ]
  STUN_SHA="$(curl -fsSL "https://raw.githubusercontent.com/pradt2/always-online-stun/$STUN_REV/valid_nat_testing_hosts.txt" | sha256sum | cut -d' ' -f1)"
  sed -i \
    -e "s/^STUN_LIST_VERSION:=.*/STUN_LIST_VERSION:=$STUN_REV/" \
    -e "s/^  HASH:=.*/  HASH:=$STUN_SHA/" \
    "$PKG_DIR/Makefile"
  grep -q "^STUN_LIST_VERSION:=$STUN_REV$" "$PKG_DIR/Makefile"
  grep -q "^  HASH:=$STUN_SHA$" "$PKG_DIR/Makefile"
else
  log "No STUN_LIST_VERSION in net/comrade -- skipping the pin bump"
fi

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

# Each step's commits become a bullet list of `owner/repo@hash` references,
# GitHub's own autolink syntax for a commit in another repository -- left
# unfenced (no code block) so GitHub actually renders the links instead of
# showing literal text. openwrt/packages' formalities bot caps a commit
# body line at 100 columns (.github/formalities.json's max_body_line_len);
# a "- dangowrt/comrade@hash " prefix plus a longer commit subject routinely
# blows past that on its own, so wrap each bullet at 96, continuation lines
# indented two spaces to read as part of the same bullet rather than a new
# one.
wrap_bullets() {
  awk '
    {
      hash = $1
      $1 = ""
      sub(/^ /, "")
      text = "- dangowrt/comrade@" hash " " $0
      width = 96
      indent = "  "
      line = ""
      n = split(text, words, " ")
      for (i = 1; i <= n; i++) {
        cand = (line == "" ? words[i] : line " " words[i])
        if (length(cand) > width && line != "") {
          print line
          line = indent words[i]
        } else {
          line = cand
        }
      }
      if (line != "") print line
    }
  '
}

log "Build the changelog for the PR description"
# --reverse so commits within a step read oldest first, same direction as
# the steps themselves (v$OLD_V's successor first, v$V last): one
# consistent chronological read top to bottom, not steps going forward in
# time while each step's own commits count backward.
CHANGELOG=""
prev="v$OLD_V"
for t in "${STEP_TAGS[@]}"; do
  if git -C "$COMRADE_DIR" rev-parse -q --verify "refs/tags/$prev" >/dev/null; then
    step="$(git -C "$COMRADE_DIR" log --oneline --reverse "$prev..$t" | wrap_bullets)"
  else
    step="(v$OLD_V is not a tag here; showing the last 20 commits up to $t)

$(git -C "$COMRADE_DIR" log --oneline --reverse -n 20 "$t" | wrap_bullets)"
  fi
  CHANGELOG="${CHANGELOG:+$CHANGELOG$'\n\n'}### $t

$step"
  prev="$t"
done

# A compare link needs a real v$OLD_V tag on the near end; when there is
# none (same fallback as the changelog above), point at the release
# itself instead of a compare URL GitHub would 404 on.
if git -C "$COMRADE_DIR" rev-parse -q --verify "refs/tags/v$OLD_V" >/dev/null \
   && [ "$OLD_V" != "$V" ]; then
  COMMIT_REF="Upstream changes:
https://github.com/dangowrt/comrade/compare/v$OLD_V...v$V"
else
  COMMIT_REF="Upstream changes:
https://github.com/dangowrt/comrade/releases/tag/v$V"
fi

log "Commit and force-push over whatever was on $BRANCH before"
git add "$PKG_DIR/Makefile"
if [ -n "$ADOPT_PR" ]; then
  # Squash the bump into the branch's single commit: the subject's version
  # moves along, the compare/tag links move with it, and the rest of the
  # message -- the PR's story may be bigger than this bump -- stands, its
  # Signed-off-by included.
  MSG="$(git log -1 --format=%B | sed -E \
    -e "1s/update to v?[0-9][0-9.a-z-]*/update to $V/" \
    -e "s|(compare/v[0-9][0-9.]*\.\.\.)v[0-9][0-9.]*|\\1v$V|" \
    -e "s|(releases/tag/)v[0-9][0-9.]*|\\1v$V|")"
  git commit --quiet --amend -m "$MSG"
else
  git commit --quiet --signoff -m "$TITLE" -m "$COMMIT_REF"
fi
# The PR title follows the commit subject: an adopted PR's subject may say
# more than "update to $V", and the two must not drift apart.
TITLE="$(git log -1 --format=%s)"
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

# Through the plain REST endpoints rather than gh's PR porcelain: `gh pr
# edit` fronts a GraphQL query whose review/team fields demand read:org on
# the openwrt organisation, which the minimal public_repo token deliberately
# lacks -- first bitten the first time the adoption path actually ran. The
# REST calls need nothing beyond public_repo on a public repository.
if [ -n "$ADOPT_PR" ]; then
  log "Replacing PR #$ADOPT_PR's title and description"
  gh api --silent -X PATCH "repos/$UPSTREAM_REPO/pulls/$ADOPT_PR" \
    -f title="$TITLE" -F "body=@$BODY"
else
  log "Opening the PR"
  gh api --silent -X POST "repos/$UPSTREAM_REPO/pulls" \
    -f base=master -f head="dangowrt:$BRANCH" \
    -f title="$TITLE" -F "body=@$BODY"
fi
