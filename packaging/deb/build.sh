#!/bin/sh
# Build comrade and its three not-yet-in-Debian dependencies as separate binary
# .deb packages for the architecture of the container this runs in.
#
# comrade depends on kcp, jech/dht and libjuice, none of which Debian packages
# yet. Rather than vendor them into the comrade binary, this channel ships them
# as their own runtime library packages (libkcp0, libdht0, libjuiceN) in the
# same apt repository, so comrade links them dynamically and stays an ordinary
# consumer of shared libraries. All four .debs land in $OUTDIR.
#
# The toolchain and the three dependency libraries are the build prerequisites,
# split into packaging/deb/prereqs.sh and baked into the intermediate builder
# image (packaging/deb/Dockerfile) so they are not rebuilt on every package
# build. If they are not already present -- a bare debian:<suite> container
# rather than the prebuilt image -- prereqs.sh is run here first, so this script
# still builds everything end to end on its own.
#
# Run inside a debian:<suite> container that matches the target arch (native, or
# under qemu-user for a foreign arch). Expects to run as root.
#
#   SRCDIR   comrade source checkout            (default /src)
#   OUTDIR   where the .deb files are written   (default /out)
#   SUITE    debian suite, informational only   (default = container's)
#
set -eu

SRCDIR="${SRCDIR:-/src}"
OUTDIR="${OUTDIR:-/out}"

# Dependency versions, shared with every other packaging pipeline.
. "$SRCDIR/packaging/versions.sh"

log() { printf '\n=== %s ===\n' "$*"; }

# Build prerequisites: the apt toolchain and the three dependency libraries in
# /usr. The prebuilt builder image carries them (and the sentinel); a bare
# debian container does not, so build them now.
if [ ! -e /usr/local/share/comrade-deb-prereqs.done ]; then
	sh "$SRCDIR/packaging/deb/prereqs.sh"
fi

TRIPLET="$(dpkg-architecture -qDEB_HOST_MULTIARCH)"
DEB_ARCH="$(dpkg-architecture -qDEB_HOST_ARCH)"
LIBDIR="/usr/lib/$TRIPLET"
NPROC="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"

# Debian's hardening flags (PIE, RELRO, BIND_NOW, FORTIFY, stack-protector).
# BIND_NOW in particular resolves every relocation at load, so the smoke test
# below is a real check that comrade exports the four symbols jech/dht leaves
# undefined for it to supply.
CFLAGS="$(dpkg-buildflags --get CFLAGS) $(dpkg-buildflags --get CPPFLAGS)"
LDFLAGS="$(dpkg-buildflags --get LDFLAGS)"

# Version and build date come from the commit being built. A tagged release
# carries the tag's version (e.g. 0.1.0, passed in as COMRADE_VERSION); an
# untagged build (a dry run or a hand build) falls back to a monotonic "~git"
# snapshot of 0.1.0 stamped with the commit's UTC time, so apt still sees an
# upgrade. SOURCE_DATE_EPOCH (which the CMake build honours) makes a given commit
# build the same bytes. The libraries keep their real upstream versions.
if git -C "$SRCDIR" rev-parse --git-dir >/dev/null 2>&1; then
	SOURCE_DATE_EPOCH="$(git -C "$SRCDIR" log -1 --format=%ct)"
	export SOURCE_DATE_EPOCH
	_stamp="$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y%m%d%H%M%S)"
	_sha="$(git -C "$SRCDIR" rev-parse --short=8 HEAD)"
	: "${COMRADE_VERSION:=0.1.0~git${_stamp}.g${_sha}}"
else
	: "${COMRADE_VERSION:=0.1.0~git0.gunknown}"
fi

WORK="$(mktemp -d)"
STAGE="$WORK/stage"
mkdir -p "$STAGE" "$OUTDIR"

# ---------------------------------------------------------------------------
log "Build comrade (against the shared deps in the builder image)"
# CI exports COMRADE_WERROR=1 to fail on any comrade warning; distribution and
# hand builds leave it unset, so a newer compiler's new warnings never break
# packaging. "1" is a truthy CMake boolean; unset resolves to OFF.
cmake -S "$SRCDIR" -B "$WORK/comrade" -G Ninja \
	-DCMAKE_BUILD_TYPE=None \
	-DCMAKE_INSTALL_PREFIX=/usr \
	-DCMAKE_PREFIX_PATH=/usr \
	-DCMAKE_C_FLAGS="$CFLAGS" \
	-DCMAKE_EXE_LINKER_FLAGS="$LDFLAGS" \
	-DCOMRADE_WERROR="${COMRADE_WERROR:-OFF}" \
	-DBUILD_TESTING=OFF
cmake --build "$WORK/comrade" -j "$NPROC"

log "Smoke test the freshly built binary"
"$WORK/comrade/comrade" --help >/dev/null
echo "comrade --help: ok (all relocations resolved under BIND_NOW)"


JUICE_REAL="$(ls "$LIBDIR"/libjuice.so.[0-9]* | head -1)"
JUICE_SONAME="$(objdump -p "$JUICE_REAL" | awk '/SONAME/{print $2; exit}')"
JUICE_PKG="lib$(echo "$JUICE_SONAME" | sed -n 's/^libjuice\.so\.\([0-9]*\).*/juice\1/p')"

# ---------------------------------------------------------------------------
# Package assembly. Depends for system libraries are read straight from each
# ELF's DT_NEEDED and mapped to the owning dpkg package, so the correct names
# fall out per arch and suite (including Debian's 64-bit time_t renames such as
# libssl3 -> libssl3t64). Our own three libraries are not dpkg-owned here, so
# they are skipped by this scan and named explicitly on comrade's Depends.
sys_depends() { # elf-file... -> "pkg (>= ver), pkg (>= ver)"
	for _f in "$@"; do
		objdump -p "$_f" 2>/dev/null | awk '/NEEDED/{print $2}'
	done | sort -u | while read -r _soname; do
		_path=""
		for d in "$LIBDIR" "/lib/$TRIPLET" /usr/lib /lib; do
			[ -e "$d/$_soname" ] && { _path="$d/$_soname"; break; }
		done
		[ -n "$_path" ] || continue
		_pkg="$(dpkg -S "$_path" 2>/dev/null | head -1 | cut -d: -f1)"
		[ -n "$_pkg" ] || continue
		_ver="$(dpkg-query -W -f='${Version}' "$_pkg" 2>/dev/null)"
		# Depend on the upstream version, not the build container's exact Debian
		# revision: a point-release/security bump (e.g. libssh-4 0.11.5-0+deb13u1)
		# keeps the soname and ABI, so pinning it would refuse an as-yet-unpatched
		# stable system. Strip the Debian revision (everything after the last "-").
		_ver="${_ver%-*}"
		printf '%s (>= %s)\n' "$_pkg" "$_ver"
	done | sort -u | paste -sd, - | sed 's/,/, /g'
}

mkdeb() { # pkgname version section "extra-depends" description-file rootdir [recommends]
	_name="$1"; _ver="$2"; _sect="$3"; _extra="$4"; _descf="$5"; _root="$6"
	_rec="${7:-}"
	mkdir -p "$_root/DEBIAN"
	_elf="$(find "$_root" -type f \( -name '*.so.*' -o -perm -111 \) \
		-exec sh -c 'file -b "$1" | grep -q ELF && echo "$1"' _ {} \; 2>/dev/null)"
	_sys="$(sys_depends $_elf)"
	_dep="$_sys"
	[ -n "$_extra" ] && _dep="${_dep:+$_dep, }$_extra"
	_size="$(du -sk "$_root" | cut -f1)"
	{
		echo "Package: $_name"
		echo "Version: $_ver"
		echo "Architecture: $DEB_ARCH"
		echo "Maintainer: Daniel Golle <daniel@makrotopia.org>"
		echo "Installed-Size: $_size"
		[ -n "$_dep" ] && echo "Depends: $_dep"
		[ -n "$_rec" ] && echo "Recommends: $_rec"
		echo "Section: $_sect"
		echo "Priority: optional"
		echo "Homepage: https://github.com/dangowrt/comrade"
		cat "$_descf"
	} > "$_root/DEBIAN/control"
	( cd "$_root" && find . -path ./DEBIAN -prune -o -type f -print0 |
		xargs -0 md5sum 2>/dev/null | sed 's,  \./,  ,' > DEBIAN/md5sums ) || true
	dpkg-deb --root-owner-group -Zxz --build "$_root" \
		"$OUTDIR/${_name}_${_ver}_${DEB_ARCH}.deb"
}

log "Assemble .deb packages"

# libjuice runtime: soname symlink + the real object, never the bare .so.
JR="$STAGE/juice"; mkdir -p "$JR$LIBDIR"
cp -a "$LIBDIR"/libjuice.so.[0-9]* "$JR$LIBDIR/"
printf 'Description: UDP Interactive Connectivity Establishment (ICE) library\n %s\n' \
	"Lightweight ICE (RFC 8445) with STUN, for peer-to-peer UDP hole punching." > "$WORK/juice.desc"
mkdeb "$JUICE_PKG" "$JUICE_VERSION" libs "" "$WORK/juice.desc" "$JR"

KR="$STAGE/kcp"; mkdir -p "$KR$LIBDIR"
cp -a "$LIBDIR"/libkcp.so.[0-9]* "$KR$LIBDIR/"
printf 'Description: KCP, a fast and reliable ARQ protocol over UDP\n %s\n' \
	"A TCP-like reliable ordered stream over an unreliable datagram transport." > "$WORK/kcp.desc"
mkdeb libkcp0 "$KCP_VERSION" libs "" "$WORK/kcp.desc" "$KR"

DR="$STAGE/dht"; mkdir -p "$DR$LIBDIR"
cp -a "$LIBDIR"/libdht.so.0 "$DR$LIBDIR/"
printf 'Description: Kademlia distributed hash table (mainline DHT) library\n %s\n' \
	"jech/dht: the BitTorrent mainline DHT as a reusable library." > "$WORK/dht.desc"
mkdeb libdht0 "$DHT_VERSION" libs "" "$WORK/dht.desc" "$DR"

# comrade: install into a package root, then name its dependency on our own
# three libraries explicitly (the ELF scan cannot map them to a package).
CR="$STAGE/comrade"
DESTDIR="$CR" cmake --install "$WORK/comrade" >/dev/null
COMRADE_LIBDEPS="$JUICE_PKG (>= $JUICE_VERSION), libkcp0 (>= $KCP_VERSION), libdht0 (>= $DHT_VERSION)"
{
	printf 'Description: Serverless peer-to-peer terminal sharing\n'
	printf ' Peer-to-peer terminal sharing with tmate-like semantics and no central\n'
	printf ' server: a host shares a tmux session, a client joins it with a token\n'
	printf ' passed out-of-band. Rendezvous on the BitTorrent mainline DHT (or LAN\n'
	printf ' multicast), ICE hole punching, and an end-to-end SSH session wrapping\n'
	printf ' stock tmux with the host key pinned in the token.\n'
} > "$WORK/comrade.desc"
# tmux is only needed to host a session, not to join one: a recommendation, not
# a hard dependency, so a join-only install stays minimal.
mkdeb comrade "$COMRADE_VERSION" net "$COMRADE_LIBDEPS" "$WORK/comrade.desc" "$CR" tmux

log "Built packages"
ls -l "$OUTDIR"/*.deb
rm -rf "$WORK"
