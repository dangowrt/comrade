# Homebrew tap (macOS)

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
brew trust dangowrt/comrade   # Homebrew 4.3+ requires trusting a third-party tap
brew install comrade          # hosting a session also needs: brew install tmux
```

## Updates

Each tagged release publishes a prebuilt **bottle** per macOS arch, and the CI
pins this tap's `comrade` formula to that release: a stable `url` at the tag's
commit plus the matching bottle block. So `brew install comrade` fetches a binary
rather than compiling on the user's machine, and `brew upgrade` moves to the next
release. `brew install --HEAD comrade` still builds the current tip of `main` for
anyone who wants it; the build date comes from the commit itself
(`SOURCE_DATE_EPOCH`, honoured by the CMake build), so a given commit always
builds the same bytes.

The release CI builds the bottle and pushes the updated formulae to the tap repo
**dangowrt/homebrew-comrade** under `Formula/` (also when a dependency version is
bumped). It needs a token with write access to that repo, exposed as the
`HOMEBREW_TAP_TOKEN` secret, the macOS counterpart of the apt repo's signing
secret.

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
