# comrade on winget

Users install comrade on Windows with:

```
winget install dangowrt.comrade
```

It is a **portable** package: winget downloads the single `comrade-<arch>.exe`
(x64 or arm64) from the GitHub release and puts it on `PATH` as `comrade`. No
installer, no bundle, one static executable that imports only system DLLs.

Hosting a session also needs tmux; joining never does. On Windows the friendly
path is the native ConPTY tmux, also from winget:

```
winget install arndawg.tmux-windows
```

comrade detects tmux automatically and, when it is missing, prints (and on a
real terminal offers to run) that exact command.

## How the manifest is produced

The three YAML files here are templates. The release CI's `winget-manifest` job,
once `comrade-x64.exe` and `comrade-arm64.exe` are built, fills the placeholders
(`@VERSION@`, `@TAG@`, `@DATE@`, the two `@SHA256_*@`) from those executables and
the tag they are released under, producing the manifest ready for submission.

- `dangowrt.comrade.yaml` — version manifest
- `dangowrt.comrade.installer.yaml` — the two per-arch portable installers
- `dangowrt.comrade.locale.en-US.yaml` — name, publisher, description, licence

## Publishing

The public `microsoft/winget-pkgs` community repository validates a manifest by
downloading its `InstallerUrl`, so the release assets (and thus the repository)
must be **public** -- which they now are. The CI keeps the manifest current for
each tagged release; submitting it to `winget-pkgs` (so `winget install
dangowrt.comrade` resolves for everyone) is the remaining one-off step. A private
winget source can consume the same manifest directly.
