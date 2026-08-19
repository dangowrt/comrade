# Single source of truth for the versions of comrade's bundled dependencies.
#
# Every in-repo packaging pipeline reads this file so they can never drift: the
# deb builder (packaging/deb/prereqs.sh and build.sh source it), the CI build
# workflow (.github/workflows/build.yml sources it), and the Windows build
# (packaging/windows/build.ps1 parses it, since PowerShell cannot source sh).
#
# The Homebrew formulae and Arch PKGBUILDs live in their own ecosystems and
# cannot read this file; keep them in step by hand when a version changes here.
#
# Format is deliberately plain KEY=value with no shell expansion, so a non-shell
# reader can parse it line by line. libjuice tags carry a "v" prefix upstream and
# kcp tags do not; consumers add the "v" where needed rather than bake it in.

# This file is sourced, not run; its variables are used by the consumers above.
# shellcheck disable=SC2034

KCP_VERSION=2.1.1
KCP_SHA256=54d3c80928d206529f67cba6f96f2c98007182b46e3112819b200d914f96e425

JUICE_VERSION=1.7.3
JUICE_SHA256=86e075ca4732882746b6d5733ff1b6090f942e5750df58630b191b5f00f30010

MONOCYPHER_VERSION=4.0.2

MBEDTLS_VERSION=3.6.7

LIBSSH_VERSION=0.12.2

# jech/dht ships no releases, so it is pinned by commit; DHT_VERSION is the
# date-based version the library packages carry.
DHT_COMMIT=0bbb8f4a5bd914b60de5e9fbb51573aa33a1cf18
DHT_VERSION=2023.03.18
