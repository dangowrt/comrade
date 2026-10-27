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

JUICE_VERSION=1.7.4
JUICE_SHA256=95c088862aa1b88b73d62aa99577135010eb768fcafb252d13aa85a8515ef798

MONOCYPHER_VERSION=4.0.3
MONOCYPHER_SHA256=8cc9bc341a66249016db9bd70e9142d8d0aef9945973744b1ac05dbc55d8ee66

MBEDTLS_VERSION=3.6.7
MBEDTLS_SHA256=a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6

LIBSSH_VERSION=0.12.2
LIBSSH_SHA256=49560f677d96e3706a904ac2de1116e25f3680937d51e5c92198fcba4a1c1e9f

DHT_VERSION=0.28
DHT_SHA256=2f91db29636ca84503b4bb59d7a4a6a681c3a547e12ef775f83e99b69be92f2d
# The library packages carried a date-based version before the tag was
# followed, and 0.28 sorts below it, so their version keeps an epoch.
DHT_PKG_EPOCH=1
