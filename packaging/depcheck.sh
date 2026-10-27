#!/bin/bash
# What the bundled dependencies are pinned at, against what upstream released.
# A pin here records what was last verified, never a requirement: comrade's
# build constrains no dependency beyond libgcrypt>=1.10, a real API floor.
# Usage: packaging/depcheck.sh [--update]
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
V=packaging/versions.sh
. "$V"

UPDATE=0
[ "${1:-}" = --update ] && UPDATE=1

behind=0
report=""

note() { report="$report$1"$'\n'; }

latest_gh_tag() {
	gh api "repos/$1/tags" --paginate --jq '.[].name' 2>/dev/null |
		sed "s/^$2//" | grep -E '^[0-9]+(\.[0-9]+)+$' |
		{ [ -n "${3:-}" ] && grep -E "$3" || cat; } |
		sort -V | tail -1
}

latest_gh_release() {
	gh api "repos/$1/releases" --paginate \
		--jq '.[] | select(.prerelease==false) | .tag_name' 2>/dev/null |
		sed "s/^$2//" | grep -E '^[0-9]+(\.[0-9]+)+$' |
		{ [ -n "${3:-}" ] && grep -E "$3" || cat; } |
		sort -V | tail -1
}

# The hash of empty input means the fetch failed, not that the file is empty.
sha_of() {
	local h
	h=$(curl -fsSL --retry 3 "$1" 2>/dev/null | sha256sum | cut -d' ' -f1)
	[ "$h" = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 ] &&
		return 1
	printf '%s' "$h"
}

check() {
	local name="$1" have="$2" want="$3" url="$4" shavar="$5" vervar="$6"
	local sha

	if [ -z "$want" ]; then
		note "$(printf '%-12s %-10s %s' "$name" "$have" 'UPSTREAM QUERY FAILED')"
		behind=1
		return
	fi
	if [ "$have" = "$want" ]; then
		note "$(printf '%-12s %-10s up to date' "$name" "$have")"
		return
	fi
	behind=1
	sha=$(sha_of "$url")
	note "$(printf '%-12s %-10s BEHIND -> %s' "$name" "$have" "$want")"
	note "$(printf '%-12s %-10s   %s' '' '' "$url")"
	note "$(printf '%-12s %-10s   sha256 %s' '' '' "${sha:-UNAVAILABLE}")"
	[ "$UPDATE" = 1 ] && [ -n "$sha" ] || return
	sed -i "s|^$vervar=.*|$vervar=$want|" "$V"
	[ -n "$shavar" ] && sed -i "s|^$shavar=.*|$shavar=$sha|" "$V"
	note "$(printf '%-12s %-10s   versions.sh updated' '' '')"
}

J=$(latest_gh_tag paullouisageneau/libjuice v)
check libjuice "$JUICE_VERSION" "$J" \
	"https://github.com/paullouisageneau/libjuice/archive/refs/tags/v$J.tar.gz" \
	JUICE_SHA256 JUICE_VERSION

K=$(latest_gh_tag skywind3000/kcp "")
check kcp "$KCP_VERSION" "$K" \
	"https://github.com/skywind3000/kcp/archive/refs/tags/$K.tar.gz" \
	KCP_SHA256 KCP_VERSION

M=$(latest_gh_tag LoupVaillant/Monocypher "")
check monocypher "$MONOCYPHER_VERSION" "$M" \
	"https://monocypher.org/download/monocypher-$M.tar.gz" \
	MONOCYPHER_SHA256 MONOCYPHER_VERSION

# mbedTLS 4 is a new major that libssh 0.12 does not build against.
T=$(latest_gh_release Mbed-TLS/mbedtls mbedtls- '^3\.')
check mbedtls "$MBEDTLS_VERSION" "$T" \
	"https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-$T/mbedtls-$T.tar.bz2" \
	MBEDTLS_SHA256 MBEDTLS_VERSION

# libssh is not on GitHub; its GitLab mirror carries the release tags.
S=$(curl -fsSL --retry 3 \
	"https://gitlab.com/api/v4/projects/libssh%2Flibssh-mirror/repository/tags?per_page=100" \
	2>/dev/null | tr ',' '\n' | sed -n 's/.*"name":"libssh-\([0-9.]*\)".*/\1/p' |
	grep -E '^[0-9]+(\.[0-9]+)+$' | sort -V | tail -1)
check libssh "$LIBSSH_VERSION" "$S" \
	"https://www.libssh.org/files/${S%.*}/libssh-$S.tar.xz" \
	LIBSSH_SHA256 LIBSSH_VERSION

# Tagged dht-X.Y upstream, so the commit pin follows the tag.
D=$(latest_gh_tag jech/dht dht- "")
DURL="https://github.com/jech/dht/archive/refs/tags/dht-$D.tar.gz"
if [ -n "$D" ] && [ "$DHT_VERSION" != "$D" ]; then
	behind=1
	dsha=$(sha_of "$DURL")
	note "$(printf '%-12s %-10s BEHIND -> %s' dht "$DHT_VERSION" "$D")"
	note "$(printf '%-12s %-10s   %s' '' '' "$DURL")"
	note "$(printf '%-12s %-10s   sha256 %s' '' '' "${dsha:-UNAVAILABLE}")"
	if [ "$UPDATE" = 1 ] && [ -n "$dsha" ]; then
		sed -i "s|^DHT_VERSION=.*|DHT_VERSION=$D|" "$V"
		sed -i "s|^DHT_SHA256=.*|DHT_SHA256=$dsha|" "$V"
		note "$(printf '%-12s %-10s   versions.sh updated' '' '')"
	fi
else
	note "$(printf '%-12s %-10s up to date' dht "$DHT_VERSION")"
fi

# Every packaging tree that carries its own copy of a version, which can
# therefore drift from versions.sh without anything noticing.
drift=0
tree=""

pin() { sed -n "s|$2|\\1|p" "$1" 2>/dev/null | head -1; }

agrees() {
	local label="$1" found="$2" want="$3"

	if [ -z "$found" ]; then
		tree="$tree$(printf '  %-40s %s' "$label" 'no pin found')"$'\n'
		drift=1
	elif [ "$found" = "$want" ]; then
		tree="$tree$(printf '  %-40s %-9s ok' "$label" "$found")"$'\n'
	else
		tree="$tree$(printf '  %-40s %-9s DRIFT, versions.sh says %s' \
			"$label" "$found" "$want")"$'\n'
		drift=1
	fi
}

H=packaging/homebrew
agrees "$H/libjuice.rb" \
	"$(pin $H/libjuice.rb '.*/tags/v\([0-9.]*\)\.tar\.gz.*')" "$JUICE_VERSION"
agrees "$H/kcp.rb" \
	"$(pin $H/kcp.rb '.*/tags/\([0-9.]*\)\.tar\.gz.*')" "$KCP_VERSION"
agrees "$H/libdht.rb" \
	"$(pin $H/libdht.rb '.*/tags/dht-\([0-9.]*\)\.tar\.gz.*')" "$DHT_VERSION"
agrees "$H/comrade.rb mbedtls" \
	"$(pin $H/comrade.rb '.*mbedtls-\([0-9.]*\)\.tar\.bz2.*')" "$MBEDTLS_VERSION"
agrees "$H/comrade.rb libssh" \
	"$(pin $H/comrade.rb '.*libssh-\([0-9.]*\)\.tar\.xz.*')" "$LIBSSH_VERSION"
agrees "$H/comrade.rb monocypher" \
	"$(pin $H/comrade.rb '.*monocypher-\([0-9.]*\)\.tar\.gz.*')" "$MONOCYPHER_VERSION"
agrees "$H/comrade.rb libjuice" \
	"$(pin $H/comrade.rb '.*/tags/v\([0-9.]*\)\.tar\.gz.*')" "$JUICE_VERSION"
agrees "$H/comrade.rb dht" \
	"$(pin $H/comrade.rb '.*/tags/dht-\([0-9.]*\)\.tar\.gz.*')" "$DHT_VERSION"
agrees packaging/arch/kcp/PKGBUILD \
	"$(pin packaging/arch/kcp/PKGBUILD '^pkgver=\(.*\)')" "$KCP_VERSION"

# Arch packages most of them itself, and comrade's PKGBUILD depends on those
# rather than carrying a recipe; what the distro ships is what it will build
# against, so that is what is worth reporting.
arch=""
arch_cmp() {
	local name="$1" want="$2" got

	got=$(curl -fsSL --retry 2 \
		"https://archlinux.org/packages/search/json/?name=$name" 2>/dev/null |
		sed -n 's/.*"pkgver": *"\([^"]*\)".*/\1/p' | head -1)
	if [ -z "$got" ]; then
		arch="$arch$(printf '  %-14s %-10s %s' "$name" '-' \
			'not in the Arch repos, so comrade carries it')"$'\n'
	elif [ "$got" = "$want" ]; then
		arch="$arch$(printf '  %-14s %-10s ok' "$name" "$got")"$'\n'
	else
		arch="$arch$(printf '  %-14s %-10s Arch is behind upstream %s' \
			"$name" "$got" "$want")"$'\n'
	fi
}

arch_cmp dht "$DHT_VERSION"
arch_cmp libjuice "$JUICE_VERSION"
arch_cmp libssh "$LIBSSH_VERSION"
arch_cmp kcp "$KCP_VERSION"

# The OpenWrt feed keeps its own recipe per dependency in openwrt/packages,
# and packages-pr.sh only ever bumps comrade itself.
feed=""
# A commit pin inside the tag's history is behind only by what those commits
# touched, which is worth saying rather than crying wolf over a CHANGES bump.
gap() {
	case "$1" in
	????????????????????????????????????????) ;;
	*) return 0 ;;
	esac
	gh api "repos/jech/dht/compare/$1...$2" \
		--jq '" (" + (.ahead_by|tostring) + " commits, touching "
		      + ([.files[].filename] | join(" ")) + ")"' 2>/dev/null
}

feed_pin() {
	gh api "repos/openwrt/packages/contents/$1/Makefile" --jq '.content' \
		2>/dev/null | base64 -d 2>/dev/null |
		sed -n "s/^$2:=//p" | head -1
}

feed_cmp() {
	local path="$1" key="$2" want="$3" got

	got=$(feed_pin "$path" "$key")
	if [ -z "$got" ]; then
		feed="$feed$(printf '  %-28s %s' "$path" 'unreadable')"$'\n'
		drift=1
	elif [ "$got" = "$want" ]; then
		feed="$feed$(printf '  %-28s %-26s ok' "$path" "$got")"$'\n'
	else
		feed="$feed$(printf '  %-28s %-26s BEHIND, upstream %s%s' \
			"$path" "$got" "$want" "$(gap "$got" "$want")")"$'\n'
		drift=1
	fi
}

feed_cmp libs/libjuice PKG_VERSION "$JUICE_VERSION"
feed_cmp libs/kcp PKG_VERSION "$KCP_VERSION"
feed_cmp libs/monocypher PKG_VERSION "$MONOCYPHER_VERSION"
feed_cmp libs/libssh PKG_VERSION "$LIBSSH_VERSION"
# libdht is pinned there by commit, so the tag's commit is what it must match.
feed_cmp libs/libdht PKG_SOURCE_VERSION \
	"$(gh api repos/jech/dht/tags --paginate \
		--jq ".[] | select(.name==\"dht-$DHT_VERSION\") | .commit.sha" \
		2>/dev/null)"

printf '\n%s\n' "comrade bundled dependencies, pinned against upstream:"
printf '%s' "$report"
printf '\n%s\n' "packaging trees that carry their own pin, against versions.sh:"
printf '%s' "$tree"
printf '\n%s\n' "the OpenWrt feed, which keeps its own recipes:"
printf '%s' "$feed"
printf '\n%s\n' "what Arch ships, which its comrade package depends on:"
printf '%s' "$arch"
if [ "$behind" != 0 ]; then
	printf '\n%s\n' "A dependency is behind upstream. --update moves versions.sh."
fi
if [ "$drift" != 0 ]; then
	printf '\n%s\n' "A packaging tree disagrees or is unreachable; each carries its"
	printf '%s\n' "own url and hash and has to be moved by hand."
fi
[ "$behind" = 0 ] && [ "$drift" = 0 ]
