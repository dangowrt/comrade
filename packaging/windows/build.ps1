# Build a single static comrade.exe for one llvm-mingw target triple.
#
#   pwsh packaging/windows/build.ps1 -Triple x86_64-w64-mingw32 -Toolchain <llvm-mingw-root>
#   pwsh packaging/windows/build.ps1 -Triple aarch64-w64-mingw32 -Toolchain <llvm-mingw-root>
#
# Fetches and statically builds comrade's dependencies (mbedTLS + libssh, kcp,
# monocypher, libjuice) with the llvm-mingw (clang, UCRT) cross toolchain, then
# builds comrade against them into one .exe importing only system DLLs. jech/dht
# is compiled in via COMRADE_DHT_DIR, and comrade's own crypto is monocypher, so
# mbedTLS only ever serves libssh. Self-contained and
# idempotent: dependency sources are fetched once into <Root>\src and reused.
param(
    [Parameter(Mandatory = $true)][string]$Triple,          # *-w64-mingw32
    [Parameter(Mandatory = $true)][string]$Toolchain,       # llvm-mingw root
    [string]$Root       = (Join-Path $PWD "winbuild"),      # work directory
    [string]$ComradeSrc = $PWD,                             # comrade checkout
    [string]$Out        = (Join-Path $PWD "winbuild\out"), # where comrade-<arch>.exe lands
    [string]$Werror     = "OFF",                           # CI passes ON to fail on a comrade warning
    [string]$Tests      = "OFF",                           # ON to build the test binaries too
    # Instrument the build (see COMRADE_SANITIZE in CMakeLists.txt). llvm-mingw
    # is clang, so it may carry a sanitiser runtime where MinGW's gcc does not;
    # the CMake probes for one and refuses the configure if there is none,
    # rather than quietly producing an uninstrumented binary.
    [string]$Sanitize   = "none"
)
$ErrorActionPreference = "Stop"

# Dependency versions come from the shared manifest so every pipeline builds the
# same set; see packaging/versions.sh. PowerShell cannot source an sh file, so
# parse it line by line (the file is plain KEY=value for exactly this reason).
$versions = @{}
foreach ($line in Get-Content (Join-Path $ComradeSrc "packaging/versions.sh")) {
    if ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)=(.*?)\s*$') {
        $versions[$matches[1]] = $matches[2].Trim('"')
    }
}
function Ver($k) {
    $v = $versions[$k]
    if (-not $v) { throw "packaging/versions.sh: missing $k" }
    return $v
}
$KCP     = Ver 'KCP_VERSION'
$MONO    = Ver 'MONOCYPHER_VERSION'
$JUICE   = Ver 'JUICE_VERSION'
$LIBSSH  = Ver 'LIBSSH_VERSION'
$MBEDTLS = Ver 'MBEDTLS_VERSION'
$DHT     = Ver 'DHT_COMMIT'

$src    = Join-Path $Root "src"
$bld    = Join-Path $Root "build\$Triple"
$prefix = Join-Path $Root "prefix\$Triple"
$pfx    = $prefix -replace '\\','/'
$tc     = $Toolchain
$tcfile = Join-Path $ComradeSrc "packaging\windows\toolchain-llvm-mingw.cmake"
$cc     = Join-Path $tc "bin\$Triple-clang.exe"
$ar     = Join-Path $tc "bin\llvm-ar.exe"
$objd   = Join-Path $tc "bin\llvm-objdump.exe"

New-Item -ItemType Directory -Force -Path $src,$bld,$prefix,$Out | Out-Null
$env:Path = "$tc\bin;" + $env:Path
if (-not (Test-Path $cc)) { throw "no clang driver for $Triple at $cc" }

function Step($m) { Write-Output ""; Write-Output "=== [$Triple] $m ===" }
function Run($exe, $argv) { & $exe @argv; if ($LASTEXITCODE -ne 0) { throw "$exe failed" } }
$common = @(
    "-DCMAKE_TOOLCHAIN_FILE=$tcfile",
    "-DLLVM_MINGW_ROOT=$($tc -replace '\\','/')",
    "-DLLVM_MINGW_TRIPLE=$Triple",
    "-DCMAKE_BUILD_TYPE=Release",
    "-DCMAKE_INSTALL_PREFIX=$prefix"
)

function Fetch($url, $archive, $dir, $stripped) {
    if (Test-Path (Join-Path $src $dir)) { return }
    $a = Join-Path $src $archive
    Step "fetch $dir"
    # Retry with backoff so a transient rate-limit blip does not fail the build.
    # When a job token is present (GH_TOKEN, set by CI), authenticate github.com
    # fetches so a shared-egress runner is charged per-token, not throttled by
    # the anonymous per-IP limit; a packager without a token fetches anonymously.
    $p = @{ Uri = $url; OutFile = $a; MaximumRetryCount = 5; RetryIntervalSec = 10 }
    if ($env:GH_TOKEN -and $url -like 'https://github.com/*') {
        $p.Headers = @{ Authorization = "Bearer $env:GH_TOKEN" }
        $p.PreserveAuthorizationOnRedirect = $true
    }
    Invoke-WebRequest @p
    tar -xf $a -C $src
    if ($stripped -and (Test-Path (Join-Path $src $stripped))) {
        Rename-Item (Join-Path $src $stripped) (Join-Path $src $dir)
    }
}

# --- fetch dependency sources (once) ---
Fetch "https://github.com/skywind3000/kcp/archive/refs/tags/$KCP.tar.gz" "kcp.tgz" "kcp" "kcp-$KCP"
Fetch "https://github.com/LoupVaillant/Monocypher/archive/refs/tags/$MONO.tar.gz" "mono.tgz" "monocypher" "Monocypher-$MONO"
Fetch "https://github.com/paullouisageneau/libjuice/archive/refs/tags/v$JUICE.tar.gz" "juice.tgz" "libjuice" "libjuice-$JUICE"
Fetch "https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-$MBEDTLS/mbedtls-$MBEDTLS.tar.bz2" "mbedtls.tbz" "mbedtls-$MBEDTLS" $null
Fetch "https://www.libssh.org/files/0.12/libssh-$LIBSSH.tar.xz" "libssh.txz" "libssh-$LIBSSH" $null
if (-not (Test-Path (Join-Path $src "dht"))) {
    Step "fetch dht"
    Run "git" @("clone", "https://github.com/jech/dht", (Join-Path $src "dht"))
    Run "git" @("-C", (Join-Path $src "dht"), "checkout", $DHT)
}
# kcp pins cmake 4.0 for nothing used here; relax the floor for older CI cmake.
$kcpcml = Join-Path $src "kcp\CMakeLists.txt"
(Get-Content $kcpcml) -replace 'cmake_minimum_required\(VERSION [0-9.]+\)', 'cmake_minimum_required(VERSION 3.20)' |
    Set-Content $kcpcml

# --- kcp (static) ---
Step "kcp $KCP"
Run "cmake" (@("-G","Ninja","-S","$src\kcp","-B","$bld\kcp") + $common + @("-DBUILD_SHARED_LIBS=OFF","-DBUILD_TESTING=OFF"))
Run "cmake" @("--build","$bld\kcp")
Run "cmake" @("--install","$bld\kcp")

# --- monocypher (static, hand-built; no CMake upstream) ---
Step "monocypher $MONO"
$mo = Join-Path $bld "monocypher"; New-Item -ItemType Directory -Force -Path $mo | Out-Null
Run $cc @("-std=c99","-O2","-Wall","-c","$src\monocypher\src\monocypher.c","-o","$mo\monocypher.o")
Run $cc @("-std=c99","-O2","-Wall","-I","$src\monocypher\src","-c","$src\monocypher\src\optional\monocypher-ed25519.c","-o","$mo\monocypher-ed25519.o")
Run $ar @("rcs","$mo\libmonocypher.a","$mo\monocypher.o","$mo\monocypher-ed25519.o")
New-Item -ItemType Directory -Force -Path "$prefix\include","$prefix\lib\pkgconfig" | Out-Null
Copy-Item "$src\monocypher\src\monocypher.h" "$prefix\include\" -Force
Copy-Item "$src\monocypher\src\optional\monocypher-ed25519.h" "$prefix\include\" -Force
Copy-Item "$mo\libmonocypher.a" "$prefix\lib\" -Force
@"
prefix=$pfx
exec_prefix=`${prefix}
libdir=`${exec_prefix}/lib
includedir=`${prefix}/include

Name: monocypher
Description: Boring crypto that simply works
Version: $MONO
Libs: -L`${libdir} -lmonocypher
Cflags: -I`${includedir}
"@ | Set-Content -Path "$prefix\lib\pkgconfig\monocypher.pc" -Encoding ascii

# --- libjuice (static) ---
Step "libjuice $JUICE"
Run "cmake" (@("-G","Ninja","-S","$src\libjuice","-B","$bld\libjuice") + $common + @("-DBUILD_SHARED_LIBS=OFF","-DUSE_NETTLE=OFF","-DNO_TESTS=ON"))
Run "cmake" @("--build","$bld\libjuice")
Run "cmake" @("--install","$bld\libjuice")

# --- mbedTLS (static, threading on: libssh's mbedtls threads shim requires it) ---
Step "mbedtls $MBEDTLS"
$cfg = Join-Path $src "mbedtls-$MBEDTLS\include\mbedtls\mbedtls_config.h"
$txt = Get-Content $cfg -Raw
$txt = $txt -replace '(?m)^//#define MBEDTLS_THREADING_C$',       '#define MBEDTLS_THREADING_C'
$txt = $txt -replace '(?m)^//#define MBEDTLS_THREADING_PTHREAD$', '#define MBEDTLS_THREADING_PTHREAD'
Set-Content -Path $cfg -Value $txt -Encoding ascii -NoNewline
Run "cmake" (@("-G","Ninja","-S","$src\mbedtls-$MBEDTLS","-B","$bld\mbedtls") + $common + @("-DENABLE_TESTING=OFF","-DENABLE_PROGRAMS=OFF","-DUSE_STATIC_MBEDTLS_LIBRARY=ON","-DUSE_SHARED_MBEDTLS_LIBRARY=OFF","-DMBEDTLS_FATAL_WARNINGS=OFF"))
Run "cmake" @("--build","$bld\mbedtls")
Run "cmake" @("--install","$bld\mbedtls")

# --- libssh (static, mbedTLS backend, server on, no sftp/zlib/gssapi) ---
Step "libssh $LIBSSH"
Run "cmake" (@("-G","Ninja","-S","$src\libssh-$LIBSSH","-B","$bld\libssh") + $common + @(
    "-DBUILD_SHARED_LIBS=OFF","-DWITH_MBEDTLS=ON","-DMBEDTLS_ROOT_DIR=$pfx",
    "-DWITH_ZLIB=OFF","-DWITH_GSSAPI=OFF","-DWITH_NACL=OFF","-DWITH_PCAP=OFF",
    "-DWITH_EXAMPLES=OFF","-DUNIT_TESTING=OFF","-DWITH_SERVER=ON","-DWITH_SFTP=OFF",
    "-DCMAKE_FIND_ROOT_PATH=$pfx;$($tc -replace '\\','/')/$Triple"))
Run "cmake" @("--build","$bld\libssh")
Run "cmake" @("--install","$bld\libssh")

# --- comrade ---
Step "comrade"
$env:PKG_CONFIG_LIBDIR = "$pfx/lib/pkgconfig"
$env:PKG_CONFIG_PATH = ""
Run "cmake" @("-G","Ninja","-S",$ComradeSrc,"-B","$bld\comrade",
    "-DCMAKE_TOOLCHAIN_FILE=$tcfile",
    "-DLLVM_MINGW_ROOT=$($tc -replace '\\','/')",
    "-DLLVM_MINGW_TRIPLE=$Triple",
    "-DCMAKE_BUILD_TYPE=Release",
    "-DCMAKE_PREFIX_PATH=$pfx",
    "-DCMAKE_FIND_ROOT_PATH=$pfx;$($tc -replace '\\','/')/$Triple",
    "-DCOMRADE_DHT_DIR=$($src -replace '\\','/')/dht",
    "-DCOMRADE_WERROR=$Werror",
    "-DCOMRADE_SANITIZE=$Sanitize",
    "-DBUILD_TESTING=$Tests")
Run "cmake" @("--build","$bld\comrade")

# --- collect the single portable exe, named by architecture ---
switch -Regex ($Triple) {
    "^x86_64"  { $arch = "x64" }
    "^aarch64" { $arch = "arm64" }
    "^i686"    { $arch = "x86" }
    default    { $arch = $Triple }
}
$exe = Join-Path $bld "comrade\comrade.exe"
$dst = Join-Path $Out "comrade-$arch.exe"
Copy-Item $exe $dst -Force
Step "artifact comrade-$arch.exe"
"size = {0:N0} bytes" -f (Get-Item $dst).Length
& $objd -f $dst | Select-Object -First 4
"--- imported DLLs ---"
& $objd -p $dst | Select-String -Pattern '^\s+DLL Name:' | ForEach-Object { $_.Line.Trim() } | Sort-Object -Unique
