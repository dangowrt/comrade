#!/bin/sh
# Assemble a signed apt repository from the .deb packages built by build.sh.
#
# The repository is laid out per suite because a package built against Debian
# stable's libraries is not the same binary as one built against testing's,
# even at the same version: each suite gets its own pool and its own dists
# tree, so an apt client only ever sees packages built for the release it runs.
#
#   INDIR    packages, grouped as $INDIR/<suite>/*.deb   (default /in)
#   REPODIR  where the apt tree is written               (default /repo)
#   SUITES   space-separated suites to publish           (default: dirs in INDIR)
#
# Signing (skipped, leaving an unsigned repo, if GPG_KEY_ID is empty):
#   GPG_KEY_ID       fingerprint or key id to sign Release with
#   GPG_PASSPHRASE   passphrase for that key (loopback pinentry)
#   GNUPGHOME        keyring holding the private key
#
set -eu

INDIR="${INDIR:-/in}"
REPODIR="${REPODIR:-/repo}"
GPG_KEY_ID="${GPG_KEY_ID:-}"
GPG_PASSPHRASE="${GPG_PASSPHRASE:-}"

ORIGIN="comrade"
LABEL="comrade"
DESCRIPTION="comrade release packages"

command -v apt-ftparchive >/dev/null 2>&1 || {
	export DEBIAN_FRONTEND=noninteractive
	apt-get update && apt-get install -y --no-install-recommends \
		apt-utils gpg gpg-agent
}

: "${SUITES:=$(cd "$INDIR" && for d in */; do [ -d "$d" ] && echo "${d%/}"; done)}"

rm -rf "$REPODIR"
mkdir -p "$REPODIR"
[ -f "$(dirname "$0")/comrade-archive-keyring.asc" ] &&
	cp "$(dirname "$0")/comrade-archive-keyring.asc" "$REPODIR/"

for SUITE in $SUITES; do
	echo "=== suite: $SUITE ==="
	POOL="pool/$SUITE/main"
	mkdir -p "$REPODIR/$POOL"
	cp "$INDIR/$SUITE"/*.deb "$REPODIR/$POOL/"

	# Architectures actually present in this suite's pool.
	ARCHES="$(for f in "$REPODIR/$POOL"/*.deb; do
			dpkg-deb -f "$f" Architecture; done | sort -u | grep -v '^all$')"

	for ARCH in $ARCHES; do
		BD="dists/$SUITE/main/binary-$ARCH"
		mkdir -p "$REPODIR/$BD"
		( cd "$REPODIR" && apt-ftparchive --arch "$ARCH" packages "$POOL" ) \
			> "$REPODIR/$BD/Packages"
		gzip -9kf "$REPODIR/$BD/Packages"
		{
			echo "Archive: $SUITE"
			echo "Component: main"
			echo "Origin: $ORIGIN"
			echo "Label: $LABEL"
			echo "Architecture: $ARCH"
		} > "$REPODIR/$BD/Release"
	done

	ARCH_LIST="$(echo "$ARCHES" | paste -sd' ' -)"
	cat > "$REPODIR/dists/$SUITE/.release.conf" <<EOF
APT::FTPArchive::Release::Origin "$ORIGIN";
APT::FTPArchive::Release::Label "$LABEL";
APT::FTPArchive::Release::Suite "$SUITE";
APT::FTPArchive::Release::Codename "$SUITE";
APT::FTPArchive::Release::Architectures "$ARCH_LIST";
APT::FTPArchive::Release::Components "main";
APT::FTPArchive::Release::Description "$DESCRIPTION";
EOF
	( cd "$REPODIR" &&
		apt-ftparchive -c "dists/$SUITE/.release.conf" release "dists/$SUITE" \
			> "dists/$SUITE/Release" )
	rm -f "$REPODIR/dists/$SUITE/.release.conf"

	if [ -n "$GPG_KEY_ID" ]; then
		echo "signing Release for $SUITE"
		gpg --batch --yes --pinentry-mode loopback \
			${GPG_PASSPHRASE:+--passphrase "$GPG_PASSPHRASE"} \
			-u "$GPG_KEY_ID" --clearsign \
			-o "$REPODIR/dists/$SUITE/InRelease" \
			"$REPODIR/dists/$SUITE/Release"
		gpg --batch --yes --pinentry-mode loopback \
			${GPG_PASSPHRASE:+--passphrase "$GPG_PASSPHRASE"} \
			-u "$GPG_KEY_ID" --detach-sign --armor \
			-o "$REPODIR/dists/$SUITE/Release.gpg" \
			"$REPODIR/dists/$SUITE/Release"
	else
		echo "GPG_KEY_ID unset: leaving $SUITE unsigned (dry run)"
	fi
done

echo "=== repository tree ==="
find "$REPODIR" -maxdepth 4 -type f | sort
