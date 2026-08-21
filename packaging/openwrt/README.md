# OpenWrt packages feed

`net/comrade/Makefile` lives upstream in **openwrt/packages**, not in this
repository -- OpenWrt builds every package from its own feed tree, not from a
recipe checked into the project it packages (the same reason the Homebrew
formulae live in a separate tap and not here). This directory holds only the
one script the release CI uses to keep that upstream Makefile in step:
`packages-pr.sh`.

## What it does

On every tag, the `openwrt-packages-pr` job clones **dangowrt/packages** (an
existing fork of openwrt/packages), rebuilds the `comrade-update` branch
fresh off upstream's current `master`, and bumps
`PKG_VERSION`/`PKG_HASH`/`PKG_RELEASE`. `comrade-update` is a fixed name, not
version-suffixed: there is only ever at most one comrade bump PR open at a
time, so the branch is a singleton by construction.

If a bump PR from an earlier release is still open on that branch, it is
**adopted**: the new commit is force-pushed over the old one and the PR's
title and description are replaced in place (same PR number throughout, so
review comments and activity stay attached to it rather than scattering
across a new PR per release). If there is no open PR -- the last one merged
or was closed -- any leftover `comrade-update` ref is deleted from the fork
first, then recreated fresh, so a merged bump never lingers as a dangling
branch and a fresh PR opens titled `comrade: update to $VERSION`.

The PR body follows openwrt/packages' own `.github/pull_request_template.md`
(Maintainer/Description/Run Testing Details/Formalities). Merging is entirely
up to OpenWrt's maintainers, same as any other contributor's PR -- this only
ever opens or adopts, never merges.

## Prerequisite

One secret, opt-in: the job guards on `OPENWRT_PACKAGES_TOKEN` being set and
skips cleanly (like `HOMEBREW_TAP_TOKEN` for the tap) so an unconfigured
fork's release run is unaffected.

- **`OPENWRT_PACKAGES_TOKEN`** -- a *classic* PAT for the dangowrt account,
  `public_repo` scope, used only for this pipeline. It has to be classic, not
  fine-grained: fine-grained PATs are rejected on `POST
  /repos/openwrt/packages/pulls` because dangowrt does not own that repo,
  even though the same token can push freely to dangowrt's own fork. This is
  a documented GitHub limitation, not a bug in the script.

The fork itself (`dangowrt/packages`) already exists; nothing to create there.

No signing key is used anywhere in this pipeline: openwrt/packages'
CONTRIBUTING.md and formalities bot only require a `Signed-off-by` trailer
with a real, non-`noreply` name and email, not a cryptographically signed
commit, so `git commit --signoff` covers it. No private key is generated,
stored as a CI secret, or handed to GitHub on the maintainer's behalf.

## Sign-off identity

Commits are authored and signed off as `Daniel Golle <daniel@makrotopia.org>`,
matching `PKG_MAINTAINER` in the Makefile -- not a bot identity.
openwrt/packages' CONTRIBUTING.md requires a real name and a real,
non-`noreply` email on the sign-off, and dangowrt is the package's registered
maintainer there already, so the automation speaks as the same identity that
would otherwise do this by hand.
