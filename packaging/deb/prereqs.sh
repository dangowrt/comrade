#!/bin/sh
# Install the build toolchain and build comrade's three not-yet-in-Debian shared
# libraries (libjuice, kcp, jech/dht) into /usr. This is the slow, rarely
# changing half of the deb pipeline: the apt install plus the per-architecture
# dependency compiles (under qemu-user for a foreign arch).
#
# It is baked into the intermediate builder image (packaging/deb/Dockerfile) so
# it runs once per suite and arch, only when a pinned version or this script
# changes, instead of on every package build. build.sh runs it on demand as
# well, so a bare debian:<suite> container still builds comrade end to end
# without the prebuilt image.
#
# Run as root inside a debian:<suite> container matching the target arch: this
# compiles natively for whatever architecture the container presents, so there
# is no cross toolchain to keep honest.
set -eu

SCRIPT_DIR="$(dirname "$0")"
# shellcheck source=packaging/versions.sh
. "$SCRIPT_DIR/../versions.sh"

log() { printf '\n=== %s ===\n' "$*"; }

log "Install build dependencies"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
	build-essential cmake ninja-build pkg-config git ca-certificates curl \
	file binutils dpkg-dev libssh-dev libssl-dev

TRIPLET="$(dpkg-architecture -qDEB_HOST_MULTIARCH)"
LIBDIR="/usr/lib/$TRIPLET"
NPROC="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"

# Debian's hardening flags (PIE, RELRO, BIND_NOW, FORTIFY, stack-protector), so
# the shipped dependency libraries carry the same hardening comrade does.
CFLAGS="$(dpkg-buildflags --get CFLAGS) $(dpkg-buildflags --get CPPFLAGS)"
LDFLAGS="$(dpkg-buildflags --get LDFLAGS)"

WORK="$(mktemp -d)"

# Authenticate github.com fetches through a job token when one is present
# (CI passes GH_TOKEN into the container), so a shared-egress runner is charged
# per-token rather than throttled by the anonymous per-IP limit. A packager
# building by hand has no token and fetches anonymously.
if [ -n "${GH_TOKEN:-}" ]; then
	git config --global \
		url."https://x-access-token:${GH_TOKEN}@github.com/".insteadOf \
		"https://github.com/"
fi

fetch_tar() { # url sha256 destdir
	_url="$1"; _sha="$2"; _dst="$3"
	mkdir -p "$_dst"
	curl --retry 5 --retry-all-errors --retry-delay 5 -fsSL "$_url" -o "$WORK/src.tar.gz"
	echo "$_sha  $WORK/src.tar.gz" | sha256sum -c -
	tar -xzf "$WORK/src.tar.gz" -C "$_dst" --strip-components=1
	rm -f "$WORK/src.tar.gz"
}

# ---------------------------------------------------------------------------
log "Build libjuice $JUICE_VERSION (shared)"
JDIR="$WORK/libjuice"
fetch_tar "https://codeload.github.com/paullouisageneau/libjuice/tar.gz/v$JUICE_VERSION" \
	"$JUICE_SHA256" "$JDIR"
cmake -S "$JDIR" -B "$JDIR/build" -G Ninja \
	-DCMAKE_BUILD_TYPE=None \
	-DCMAKE_INSTALL_PREFIX=/usr \
	-DCMAKE_INSTALL_LIBDIR="lib/$TRIPLET" \
	-DCMAKE_C_FLAGS="$CFLAGS" \
	-DCMAKE_SHARED_LINKER_FLAGS="$LDFLAGS" \
	-DNO_TESTS=ON -DUSE_NETTLE=OFF
cmake --build "$JDIR/build" -j "$NPROC"
cmake --install "$JDIR/build"

# ---------------------------------------------------------------------------
log "Build kcp $KCP_VERSION (shared, soname imposed)"
KDIR="$WORK/kcp"
fetch_tar "https://codeload.github.com/skywind3000/kcp/tar.gz/$KCP_VERSION" \
	"$KCP_SHA256" "$KDIR"
# Upstream honours BUILD_SHARED_LIBS but sets no VERSION/SOVERSION; CMake sets
# the soname itself, so a linker flag cannot win and the target property is the
# only lever. 0 is the packaged ABI epoch, bumped if the ikcp_* surface changes.
printf '\nset_target_properties(kcp PROPERTIES VERSION %s SOVERSION 0)\n' \
	"$KCP_VERSION" >> "$KDIR/CMakeLists.txt"
# Debian stable ships cmake 3.31; kcp's CMakeLists demands 4.0 for nothing we
# use here, so relax the floor rather than pull in a newer cmake just for it.
sed -i 's/cmake_minimum_required(VERSION[^)]*)/cmake_minimum_required(VERSION 3.20)/I' \
	"$KDIR/CMakeLists.txt"
cmake -S "$KDIR" -B "$KDIR/build" -G Ninja \
	-DCMAKE_BUILD_TYPE=None \
	-DCMAKE_INSTALL_PREFIX=/usr \
	-DCMAKE_INSTALL_LIBDIR="lib/$TRIPLET" \
	-DCMAKE_C_FLAGS="$CFLAGS" \
	-DCMAKE_SHARED_LINKER_FLAGS="$LDFLAGS" \
	-DBUILD_SHARED_LIBS=ON -DBUILD_TESTING=OFF
cmake --build "$KDIR/build" -j "$NPROC"
cmake --install "$KDIR/build"

# ---------------------------------------------------------------------------
log "Build libdht (jech/dht $DHT_VERSION, shared)"
DDIR="$WORK/dht"
i=0
until git clone --quiet https://github.com/jech/dht "$DDIR"; do
	i=$((i + 1)); [ "$i" -ge 5 ] && exit 1
	rm -rf "$DDIR"; sleep 5
done
git -C "$DDIR" checkout --quiet "$DHT_COMMIT"
# jech/dht ships a plain Makefile that builds a test binary, not a library, so
# the shared object is built directly (the two commands the OpenWrt and Arch
# recipes use). dht.c leaves four symbols undefined for the application to
# supply; -shared allows that, and comrade resolves them at link time.
( cd "$DDIR"
  # shellcheck disable=SC2086
  cc $CFLAGS -fPIC -Wall -c -o dht.o dht.c
  # shellcheck disable=SC2086
  cc $LDFLAGS -shared -Wl,-soname,libdht.so.0 -o libdht.so.0 dht.o )
install -Dm755 "$DDIR/libdht.so.0" "$LIBDIR/libdht.so.0"
ln -sf libdht.so.0 "$LIBDIR/libdht.so"
install -Dm644 "$DDIR/dht.h" /usr/include/dht/dht.h
ldconfig

rm -rf "$WORK"

# Sentinel so build.sh knows the toolchain and the three libraries are already
# present and can skip straight to building comrade.
mkdir -p /usr/local/share
: > /usr/local/share/comrade-deb-prereqs.done
