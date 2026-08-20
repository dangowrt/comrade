# comrade rolling-release apt channel

A signed apt repository, rebuilt from `main` and published to GitHub Pages, so
Debian and Ubuntu users install comrade and receive updates through their
package manager like any other source. No `curl | bash`, no self-updating
binary: provenance, dependency resolution and security updates stay where they
belong.

comrade depends on three libraries Debian does not package yet (kcp, jech/dht
and libjuice). Rather than fold them into the comrade binary, the channel ships
each as its own runtime library package in the same repository, so comrade
links them dynamically and stays an ordinary consumer of shared libraries:

| Package | What it is |
|---------|------------|
| `comrade` | the CLI |
| `libjuice1` | ICE/STUN hole punching (libjuice) |
| `libkcp0` | reliable stream over UDP (kcp) |
| `libdht0` | mainline DHT (jech/dht) |

`tmux` is a recommendation, needed only to host a session, so a join-only
install stays minimal.

## Using the channel

Replace the URL if you publish under a different account. The key is fetched
into apt's trusted-keyring directory and pinned to this source alone with
`signed-by`, so it can never vouch for any other repository.

    sudo install -d -m 0755 /etc/apt/keyrings
    sudo curl -fsSL https://dangowrt.github.io/comrade/comrade-archive-keyring.asc \
        -o /etc/apt/keyrings/comrade.asc
    echo "deb [signed-by=/etc/apt/keyrings/comrade.asc] https://dangowrt.github.io/comrade stable main" \
        | sudo tee /etc/apt/sources.list.d/comrade.list
    sudo apt-get update
    sudo apt-get install comrade

Use `testing` in place of `stable` on a Debian testing system. `apt-get upgrade`
then tracks the rolling release; `unattended-upgrades` keeps it current
automatically once you allow the `comrade:stable` origin.

## Coverage

Every Debian stable (trixie) and testing (forky) release architecture:
`amd64`, `arm64`, `armhf`, `i386`, `ppc64el`, `riscv64`, `s390x`. Each suite is
built in its own container so a package always matches the libraries of the
release it targets, and the two suites keep separate pools and `dists` trees.

## How it is built

- Dependency versions are pinned once in `packaging/versions.sh`, shared with
  the CI build and the Windows recipe so the channels never drift.
- `prereqs.sh` installs the build toolchain and builds the three dependencies
  (libjuice, kcp, jech/dht) as shared libraries with Debian's hardening flags.
  It is baked into an intermediate builder image (`Dockerfile`) per suite and
  architecture and cached in a local registry, so those slow per-arch compiles
  run only when a pinned version or the script changes.
- `build.sh` runs inside that image (or a bare `debian:<suite>` container, in
  which case it runs `prereqs.sh` itself), builds comrade against the shared
  libraries, and reads each package's dependencies straight from the ELF
  `NEEDED` entries, so the correct package names fall out per arch and suite
  (including the 64-bit `time_t` renames such as `libssl3` to `libssl3t64`).
- `make-repo.sh` assembles the pool and `dists` tree with `apt-ftparchive` and
  signs each suite's `Release` into `InRelease` and `Release.gpg`.
- `.github/workflows/release.yml` builds the builder images, runs `build.sh`
  across the arch and suite matrix, then `make-repo.sh` on the collected
  packages, and deploys the result to GitHub Pages. The intermediate-image
  cache is opt-in through the `COMRADE_CACHE_REGISTRY` repository variable;
  unset, the build falls back to a bare `debian` container that builds the
  prerequisites itself.

Both scripts are ordinary shell and can be run by hand to reproduce the channel
locally; see the header comments for the environment variables they take.

## Maintaining the signing key

`comrade-archive-keyring.asc` is the public half of a dedicated repository
signing key and is safe to commit. The private half signs the repository in CI
and is never committed. To wire it up:

    gh secret set COMRADE_APT_GPG_KEY < private-key.asc
    gh secret set COMRADE_APT_GPG_PASSPHRASE            # paste the passphrase

Going live then takes one further, deliberate step so that staging the key
never publishes on its own:

    gh variable set COMRADE_PUBLISH --body true

The publish job skips itself unless *both* `COMRADE_APT_GPG_KEY` is set and
`COMRADE_PUBLISH` is `true`, so merging this packaging, or staging the key to
validate signing, publishes nothing. Enable Pages for the repository (Settings,
Pages, Source: GitHub Actions) before flipping `COMRADE_PUBLISH`, or the first
live run fails on the Pages deploy. Rotate by generating a new key, replacing
the committed public key and the two secrets; clients pick up the new key the
next time they refresh it.
