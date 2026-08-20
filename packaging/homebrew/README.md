# Homebrew tap (macOS rolling release)

This directory is the **dangowrt/comrade** Homebrew tap. It carries four
formulae: `comrade` plus the three dependencies Homebrew core does not ship
(`libjuice`, `kcp`, `libdht`). Each dependency is its own formula, built as a
shared library and linked into comrade **dynamically**, the same way every other
distribution packages them (separate Debian `.deb`s, Arch packages, OpenWrt
packages). `libssh` and `openssl@3` come from Homebrew core.

libdht (jech/dht) leaves four symbols for the application (`dht_hash`,
`dht_random_bytes`, `dht_blacklisted`, `dht_sendto`); comrade defines them and is
linked with `-export_dynamic` so the shared libdht resolves them back at runtime
(the dylib itself is built with `-undefined dynamic_lookup`).

## Using it

```
brew tap dangowrt/comrade
brew install --HEAD comrade   # hosting a session also needs: brew install tmux
brew upgrade --fetch-HEAD comrade
```

## Rolling updates

comrade has no upstream tags yet, so the formula does not pin a revision: it is
`head`-only and tracks the tip of `main` directly. `brew install --HEAD` builds
the current commit, and `brew upgrade --fetch-HEAD` re-fetches main and rebuilds
whenever it has moved. There is nothing to restamp; the build date comes from
the commit itself (`SOURCE_DATE_EPOCH`, honoured by the CMake build), so a given
commit always builds the same bytes.

The `brew` CI job only keeps the tap repo **dangowrt/homebrew-comrade** in step
with the formulae in this tree (for example when a dependency version is
bumped), committing them under `Formula/`. It needs a token with write access to
that repo, exposed as the `HOMEBREW_TAP_TOKEN` secret, the macOS counterpart of
the apt repo's signing secret.

## Dependency formulae and pins

| Formula | Version / commit | Source |
|---------|------------------|--------|
| libjuice | v1.7.3 | github.com/paullouisageneau/libjuice |
| kcp | 2.1.1 | github.com/skywind3000/kcp |
| libdht | 0bbb8f4 (jech/dht) | github.com/jech/dht |

These match the pins in `.github/workflows/build.yml` and the Debian and OpenWrt
recipes. Bump them in lockstep.

## Validated

Validated on macOS (Intel, x86_64): the three dependency formulae build and
install as dylibs, comrade links all of `libdht.dylib`, `libjuice.dylib`,
`libkcp.dylib`, `libssh.4.dylib` and `libcrypto.3.dylib` dynamically (`otool -L`),
the shared libdht's application callbacks resolve at launch
(`DYLD_BIND_AT_LAUNCH=1 comrade --help` succeeds), and a live host run completes
DHT rendezvous without crashing.
