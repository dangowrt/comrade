# CMake toolchain file for llvm-mingw (clang + mingw-w64 headers/CRT, UCRT).
#
# Why clang and not the MSYS2 GCC: mingw-w64 GCC has no Windows-on-ARM target
# at all -- there is no aarch64-w64-mingw32 gcc, and MSYS2's only ARM64
# packages are `mingw-w64-clang-aarch64-*` (native ARM64 binaries, unusable as
# a cross toolchain on this AMD64 host). LLVM is a native cross-compiler, and
# llvm-mingw pairs it with the SAME mingw-w64 headers, CRT, winpthreads and
# UCRT that the Windows port chose -- so the POSIX/GNU header surface
# the plan relies on (pthread.h, sys/socket.h, partial unistd.h) is unchanged.
#
# Usage:
#   cmake -DCMAKE_TOOLCHAIN_FILE=.../toolchain-llvm-mingw.cmake \
#         -DLLVM_MINGW_TRIPLE=aarch64-w64-mingw32 ...
#
# Valid triples shipped by llvm-mingw 20260616:
#   aarch64-w64-mingw32   arm64ec-w64-mingw32   armv7-w64-mingw32
#   i686-w64-mingw32      x86_64-w64-mingw32

set(CMAKE_SYSTEM_NAME Windows)

if(NOT LLVM_MINGW_ROOT)
	set(LLVM_MINGW_ROOT
	    "C:/Users/user/winport/toolchains/llvm-mingw-20260616-ucrt-x86_64"
	    CACHE PATH "llvm-mingw installation root")
endif()
if(NOT LLVM_MINGW_TRIPLE)
	set(LLVM_MINGW_TRIPLE "aarch64-w64-mingw32"
	    CACHE STRING "llvm-mingw target triple")
endif()

if(LLVM_MINGW_TRIPLE MATCHES "^aarch64")
	set(CMAKE_SYSTEM_PROCESSOR ARM64)
elseif(LLVM_MINGW_TRIPLE MATCHES "^arm64ec")
	set(CMAKE_SYSTEM_PROCESSOR ARM64EC)
elseif(LLVM_MINGW_TRIPLE MATCHES "^armv7")
	set(CMAKE_SYSTEM_PROCESSOR ARM)
elseif(LLVM_MINGW_TRIPLE MATCHES "^i686")
	set(CMAKE_SYSTEM_PROCESSOR x86)
else()
	set(CMAKE_SYSTEM_PROCESSOR AMD64)
endif()

set(CMAKE_C_COMPILER   "${LLVM_MINGW_ROOT}/bin/${LLVM_MINGW_TRIPLE}-clang.exe")
set(CMAKE_CXX_COMPILER "${LLVM_MINGW_ROOT}/bin/${LLVM_MINGW_TRIPLE}-clang++.exe")
set(CMAKE_RC_COMPILER  "${LLVM_MINGW_ROOT}/bin/${LLVM_MINGW_TRIPLE}-windres.exe")
set(CMAKE_AR           "${LLVM_MINGW_ROOT}/bin/llvm-ar.exe")
set(CMAKE_RANLIB       "${LLVM_MINGW_ROOT}/bin/llvm-ranlib.exe")
set(CMAKE_C_COMPILER_TARGET   "${LLVM_MINGW_TRIPLE}")
set(CMAKE_CXX_COMPILER_TARGET "${LLVM_MINGW_TRIPLE}")

# Look for libraries/headers in the target sysroot and in our own per-triple
# install prefix; never pick host programs out of the sysroot.
list(APPEND CMAKE_FIND_ROOT_PATH "${LLVM_MINGW_ROOT}/${LLVM_MINGW_TRIPLE}")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
