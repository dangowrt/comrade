# comrade on Windows

One statically-linked `comrade.exe` per architecture (x64, arm64), importing
only system DLLs (`KERNEL32`, `WS2_32`, `bcrypt`, `IPHLPAPI`, `ADVAPI32`,
`SHELL32`, UCRT) — no runtime to install, no bundle, one portable file.
Joining a session needs nothing else; hosting also needs tmux, obtained
separately (`winget install arndawg.tmux-windows`, a native ConPTY tmux).

## Building

`build.ps1` builds one target triple end to end: it fetches and statically
builds the dependencies (mbedTLS + libssh, kcp, monocypher, libjuice; jech/dht
is compiled in) with the **llvm-mingw** cross toolchain, then builds comrade
against them.

```powershell
# get llvm-mingw (clang + mingw-w64 + UCRT) from
#   https://github.com/mstorsjo/llvm-mingw/releases
pwsh packaging/windows/build.ps1 `
     -Triple x86_64-w64-mingw32  -Toolchain C:\path\to\llvm-mingw
pwsh packaging/windows/build.ps1 `
     -Triple aarch64-w64-mingw32 -Toolchain C:\path\to\llvm-mingw
```

The `.exe` lands in `winbuild\out\comrade-<arch>.exe`. `toolchain-llvm-mingw.cmake`
is the CMake toolchain file (clang because mingw-w64 GCC has no Windows-on-ARM
target; llvm-mingw uses the same mingw-w64 headers/CRT/UCRT). libssh uses
**mbedTLS**; comrade's own crypto stays **monocypher**, so mbedTLS never has to
supply BLAKE2b or Ed25519.

## CI

`.github/workflows/release.yml` builds both arches on a single `windows-latest`
runner (arm64 is cross-built and compile/import-verified; it cannot execute on
an AMD64 runner), publishes the executables to the tagged GitHub release, and
fills the winget manifest templates in `packaging/winget/`.
