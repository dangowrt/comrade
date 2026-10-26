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

printf '\n%s\n' "comrade bundled dependencies, pinned against upstream:"
printf '%s' "$report"
if [ "$behind" != 0 ]; then
	printf '\n%s\n' "Behind. --update moves versions.sh; the Homebrew formulae"
	printf '%s\n' "(packaging/homebrew/*.rb) carry their own url and sha256."
fi
exit "$behind"
