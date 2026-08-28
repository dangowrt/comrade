cmake_minimum_required(VERSION 3.20)

project(comrade VERSION 0.0.1 LANGUAGES C)

include(GNUInstallDirs)
include(CTest)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Wextra)

# CI holds comrade's own code to a warning-free bar. Scoped to this directory's
# compile options, so it covers comrade's sources but not imported libraries;
# the vendored jech/dht is compiled with -w below, which keeps it exempt, and
# on Windows libssh is built by a separate CMake run that never sees this. Off
# by default so distribution and hand builds are not broken by a newer
# compiler's new warnings.
option(COMRADE_WERROR "Treat comrade's own warnings as errors (used by CI)" OFF)
if(COMRADE_WERROR)
	add_compile_options(-Werror)
endif()

include(CheckCCompilerFlag)

function(comrade_add_flag flag)
	string(MAKE_C_IDENTIFIER "comrade_have_${flag}" var)
	check_c_compiler_flag("${flag}" ${var})
	if(${var})
		add_compile_options("${flag}")
	endif()
endfunction()

# Reproducible builds: forbid __DATE__/__TIME__ and strip the build path
# from the binary so it does not identify the build host. Distributions
# inject their own comprehensive prefix maps on top of this.
comrade_add_flag(-Wdate-time)
comrade_add_flag(-ffile-prefix-map=${CMAKE_SOURCE_DIR}=.)

find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)
pkg_check_modules(LIBSSH IMPORTED_TARGET libssh)
find_package(LibJuice CONFIG QUIET)
find_package(kcp CONFIG QUIET)

#
# Windows (MinGW-w64/UCRT, x86_64 and aarch64). One comrade.exe that both
# joins and hosts: hosting's fork/forkpty/setsid are CreateProcess, a
# pseudoconsole and DETACHED_PROCESS (src/win_proc.c, src/cpty_win.c,
# src/host_win.c), and the tmux it runs is a separately installed one that is
# never bundled (src/tmuxpath.c). Everything below is about linking that
# executable self-contained, importing nothing but system DLLs.
#
if(WIN32)
	# comrade's own crypto is monocypher regardless of what libssh links.
	# libssh here is backed by mbedTLS, which implements neither BLAKE2b nor
	# Ed25519 -- both comrade wire formats -- so the "follow libssh" default
	# cannot apply; monocypher is ~100 KB and pulls in no DLL.
	set(COMRADE_CRYPTO "monocypher" CACHE STRING "" FORCE)

	# Static libssh and static libjuice both declare their API
	# __declspec(dllimport) unless told otherwise, so without these the link
	# fails on __imp_ssh_* / __imp_juice_*.
	add_compile_definitions(LIBSSH_STATIC JUICE_STATIC)

	# libssh's pkg-config file lists only -lssh; its crypto backend is a
	# private dependency that a static link still has to name. everest and
	# p256m are mbedcrypto's own bundled pieces and must follow it.
	foreach(l mbedtls mbedx509 mbedcrypto everest p256m)
		find_library(COMRADE_LIB_${l} ${l})
		if(COMRADE_LIB_${l})
			list(APPEND COMRADE_WIN_CRYPTO ${COMRADE_LIB_${l}})
		endif()
	endforeach()

	# ws2_32: sockets. bcrypt: BCryptGenRandom in keys.c, plus libjuice's
	# own crypto. iphlpapi: GetAdaptersAddresses in netmon.c.
	set(COMRADE_WIN_LIBS ws2_32 bcrypt iphlpapi ${COMRADE_WIN_CRYPTO})

	# One executable, no redistributable runtime: static libgcc/libstdc++
	# and static winpthreads, so the only imports left are system DLLs.
	set(COMRADE_WIN_LINK -static -static-libgcc)

	# The tools are POSIX-only. The tests are not all of them: what needs a
	# socketpair, a pty or a shell says so where it is defined, and the rest
	# builds here. A Windows build is usually the release one, so they stay
	# off unless asked for -- but asking now works.
	if(NOT DEFINED CACHE{BUILD_TESTING})
		set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
	endif()
	set(COMRADE_BUILD_TOOLS OFF)
else()
	set(COMRADE_BUILD_TOOLS ON)
endif()
#
# Crypto backend. Every primitive comrade needs is byte-identical across the
# backends, so the choice is purely about which library is already on the
# box: by default follow libssh's own crypto backend, so comrade never pulls
# in a second one. Override with -DCOMRADE_CRYPTO=<backend>.
#
set(COMRADE_CRYPTO "auto" CACHE STRING
	"Crypto backend: auto (follow libssh), openssl, gcrypt or monocypher")

# Which crypto library is this libssh linked against? libssh exposes that
# neither in its headers nor in its pkg-config file, so read the DT_NEEDED
# names out of the library itself. file(STRINGS) needs no external tool and
# works when cross-compiling, since it reads the target binary directly.
function(comrade_detect_libssh_crypto out)
	set(${out} "" PARENT_SCOPE)
	find_library(COMRADE_LIBSSH_PATH NAMES ssh
		HINTS ${LIBSSH_LIBRARY_DIRS} ${LIBSSH_LIBDIR})
	if(NOT COMRADE_LIBSSH_PATH)
		return()
	endif()
	file(STRINGS "${COMRADE_LIBSSH_PATH}" NEEDED
		REGEX "^lib(crypto|gcrypt|mbedcrypto)\\.so" ENCODING UTF-8)
	foreach(dep IN LISTS NEEDED)
		if(dep MATCHES "^libcrypto")
			set(${out} "openssl" PARENT_SCOPE)
			return()
		elseif(dep MATCHES "^libgcrypt")
			set(${out} "gcrypt" PARENT_SCOPE)
			return()
		elseif(dep MATCHES "^libmbedcrypto")
			set(${out} "mbedtls" PARENT_SCOPE)
			return()
		endif()
	endforeach()
endfunction()

if(COMRADE_CRYPTO STREQUAL "auto")
	comrade_detect_libssh_crypto(COMRADE_LIBSSH_CRYPTO)
	if(COMRADE_LIBSSH_CRYPTO STREQUAL "mbedtls")
		# mbedTLS implements neither BLAKE2b nor Ed25519, both of which are
		# comrade wire formats, so it cannot back ccrypto on its own.
		# Monocypher is the right partner here: ~70 KB and self-contained,
		# where falling back to libcrypto or libgcrypt would pull in the
		# megabytes a mbedTLS-based libssh was chosen to avoid.
		set(COMRADE_CRYPTO_RESOLVED "monocypher")
		set(COMRADE_CRYPTO_WHY "libssh uses mbedTLS, which has no BLAKE2b or Ed25519")
	elseif(COMRADE_LIBSSH_CRYPTO)
		set(COMRADE_CRYPTO_RESOLVED "${COMRADE_LIBSSH_CRYPTO}")
		set(COMRADE_CRYPTO_WHY "follows libssh")
	else()
		set(COMRADE_CRYPTO_RESOLVED "openssl")
		set(COMRADE_CRYPTO_WHY "libssh backend not detected, assuming OpenSSL")
	endif()
else()
	set(COMRADE_CRYPTO_RESOLVED "${COMRADE_CRYPTO}")
	set(COMRADE_CRYPTO_WHY "requested")
endif()

if(COMRADE_CRYPTO_RESOLVED STREQUAL "mbedtls")
	message(FATAL_ERROR
		"COMRADE_CRYPTO=mbedtls is not possible on its own: mbedTLS "
		"implements neither BLAKE2b nor Ed25519, which comrade needs on the "
		"wire. Use -DCOMRADE_CRYPTO=monocypher (small and self-contained) "
		"alongside a mbedTLS-based libssh.")
endif()

if(COMRADE_CRYPTO_RESOLVED STREQUAL "monocypher")
	pkg_check_modules(MONOCYPHER IMPORTED_TARGET monocypher)
	if(NOT MONOCYPHER_FOUND)
		find_path(MONOCYPHER_INCLUDE_DIR monocypher.h)
		find_library(MONOCYPHER_LIBRARY monocypher)
		if(MONOCYPHER_INCLUDE_DIR AND MONOCYPHER_LIBRARY)
			set(MONOCYPHER_FOUND 1)
		endif()
	endif()
elseif(COMRADE_CRYPTO_RESOLVED STREQUAL "openssl")
	find_package(OpenSSL QUIET)
elseif(COMRADE_CRYPTO_RESOLVED STREQUAL "gcrypt")
	pkg_check_modules(GCRYPT IMPORTED_TARGET libgcrypt)
	if(NOT GCRYPT_FOUND)
		find_path(GCRYPT_INCLUDE_DIR gcrypt.h)
		find_library(GCRYPT_LIBRARY gcrypt)
		if(GCRYPT_INCLUDE_DIR AND GCRYPT_LIBRARY)
			set(GCRYPT_FOUND 1)
		endif()
	endif()
else()
	message(FATAL_ERROR "COMRADE_CRYPTO must be auto, openssl, gcrypt or "
		"monocypher, not '${COMRADE_CRYPTO}'")
endif()
message(STATUS "Crypto backend: ${COMRADE_CRYPTO_RESOLVED} (${COMRADE_CRYPTO_WHY})")

set(COMRADE_DHT_DIR "" CACHE PATH "Directory containing dht.c and dht.h from jech/dht")

# Core components. comrade is a secure peer-to-peer tool, and every one of
# these is load-bearing: a crypto backend seals and signs the wire, kcp is the
# transport, libssh wraps it, libjuice punches the path, and jech/dht is the
# rendezvous. There is no useful or safe subset, so a missing one is a hard
# configure error, never a degraded build.
set(COMRADE_MISSING "")
if(NOT LIBSSH_FOUND)
	list(APPEND COMRADE_MISSING "libssh (pkg-config module libssh)")
endif()
if(NOT TARGET LibJuice::LibJuice)
	list(APPEND COMRADE_MISSING "libjuice (CMake package LibJuice)")
endif()
if(NOT TARGET kcp::kcp)
	list(APPEND COMRADE_MISSING "kcp (CMake package kcp)")
endif()
if(COMRADE_CRYPTO_RESOLVED STREQUAL "monocypher")
	if(NOT MONOCYPHER_FOUND)
		list(APPEND COMRADE_MISSING "monocypher (pkg-config module or monocypher.h + libmonocypher)")
	endif()
elseif(COMRADE_CRYPTO_RESOLVED STREQUAL "gcrypt")
	if(NOT GCRYPT_FOUND)
		list(APPEND COMRADE_MISSING "libgcrypt (pkg-config module or gcrypt.h + libgcrypt)")
	endif()
elseif(NOT TARGET OpenSSL::Crypto)
	list(APPEND COMRADE_MISSING "OpenSSL libcrypto (CMake package OpenSSL)")
endif()
# Either route to jech/dht satisfies the build (see the comrade_dht block).
find_path(COMRADE_DHT_INCLUDE_DIR dht.h PATH_SUFFIXES dht)
find_library(COMRADE_DHT_LIBRARY dht)
if(NOT (COMRADE_DHT_DIR AND EXISTS "${COMRADE_DHT_DIR}/dht.c") AND
   NOT (COMRADE_DHT_INCLUDE_DIR AND COMRADE_DHT_LIBRARY))
	list(APPEND COMRADE_MISSING
		"dht (installed libdht, or a jech/dht checkout via COMRADE_DHT_DIR)")
endif()
if(COMRADE_MISSING)
	list(JOIN COMRADE_MISSING "\n   " COMRADE_MISSING_TEXT)
	message(FATAL_ERROR
		"comrade cannot be built without its core components -- it is complete "
		"and secure, or it does not build. Install the missing pieces and "
		"reconfigure. Missing:\n   ${COMRADE_MISSING_TEXT}")
endif()

#
# Platform compat: sockets/poll (wsock), the local terminal (tty) and the few
# remaining OS calls that differ (oscompat). On POSIX these compile to what
# the code always did; on Windows they are where winsock, the console API and
# the missing fork/rename semantics are dealt with, once, instead of as
# #ifdefs spread through the modules.
#
add_library(comrade_compat STATIC src/wsock.c src/tty.c src/oscompat.c)
target_include_directories(comrade_compat PUBLIC src)
target_link_libraries(comrade_compat PUBLIC Threads::Threads)
if(WIN32)
	target_link_libraries(comrade_compat PUBLIC ${COMRADE_WIN_LIBS})
endif()

add_library(comrade_token STATIC src/base64.c src/base58.c src/token.c src/tokgen.c)
target_include_directories(comrade_token PUBLIC src)

# Per-user application data directory (STUN list, cached DHT nodes).
add_library(comrade_appdir STATIC src/appdir.c)
target_include_directories(comrade_appdir PUBLIC src)
target_link_libraries(comrade_appdir PUBLIC comrade_compat)

# Structured connection status (controller fills it, view renders it) and the
# view that paints it on the reserved bottom terminal row.
add_library(comrade_dbg STATIC src/dbg.c)
target_include_directories(comrade_dbg PUBLIC src)
target_link_libraries(comrade_dbg PUBLIC comrade_compat)

#
# A command running on its own terminal: forkpty plus /bin/sh, or a
# pseudoconsole plus CreateProcess. Both the SSH server and the host's local
# attach drive one, and neither contains a platform #ifdef because of this.
# The Windows side brings its process helpers and the tmux search with it.
#
if(WIN32)
	add_library(comrade_cpty STATIC
		src/cpty_win.c src/win_proc.c src/tmuxpath.c)
else()
	add_library(comrade_cpty STATIC src/cpty_posix.c)
endif()
target_include_directories(comrade_cpty PUBLIC src)
target_link_libraries(comrade_cpty PUBLIC comrade_compat comrade_dbg)

add_library(comrade_termfilter STATIC src/termfilter.c)
target_include_directories(comrade_termfilter PUBLIC src)

add_library(comrade_ctlproto STATIC src/ctlproto.c)
target_include_directories(comrade_ctlproto PUBLIC src)
target_link_libraries(comrade_ctlproto PUBLIC comrade_compat)

add_library(comrade_conn STATIC src/conn.c)
target_include_directories(comrade_conn PUBLIC src)
target_link_libraries(comrade_conn PUBLIC comrade_compat)

# -L/-R forwarding-spec parsing (no dependencies; the engine lives with ssh).
add_library(comrade_fwdspec STATIC src/fwdspec.c)
target_include_directories(comrade_fwdspec PUBLIC src)

# What the threads learn about this network, on its way to the model above.
# Deliberately links nothing: a queue whose rules are about which facts may be
# lost is worth exercising without threads or a network.
add_library(comrade_nsfacts STATIC src/nsfacts.c)
target_include_directories(comrade_nsfacts PUBLIC src)

add_library(comrade_hostreap STATIC src/hostreap.c)
target_include_directories(comrade_hostreap PUBLIC src)

add_library(comrade_claimlog STATIC src/claimlog.c)
target_include_directories(comrade_claimlog PUBLIC src)

add_library(comrade_hbeat STATIC src/hbeat.c)
target_include_directories(comrade_hbeat PUBLIC src)

add_library(comrade_replay STATIC src/replay.c)
target_include_directories(comrade_replay PUBLIC src)

# Origin for stream datagrams: SSH inside KCP is already unreadable on the
# path, so what it needs is a statement of who sent it, not another cipher.
add_library(comrade_dataauth STATIC src/dataauth.c)
target_include_directories(comrade_dataauth PUBLIC src)
target_link_libraries(comrade_dataauth comrade_crypto)

# Per-family reachability: what this host knows about its own network, and what
# stops being true when it moves. Deliberately links nothing -- no sockets, no
# threads, no clock -- so it can be driven entirely from synthetic events.
add_library(comrade_netstate STATIC src/netstate.c)
target_include_directories(comrade_netstate PUBLIC src)

add_library(comrade_statusbar STATIC src/statusbar.c)
target_include_directories(comrade_statusbar PUBLIC src)
target_link_libraries(comrade_statusbar PUBLIC comrade_conn comrade_compat)

# STUN server pool. The default set is baked in at configure time from the
# always-online-stun submodule (its RFC 5780-capable list, which also serves
# for plain reflexive gathering); `comrade stun-update` refreshes it into the
# user's data folder at runtime. The list is never copied into our own tree.
# A source tree without it (GitHub tarballs carry the submodule as an empty
# directory) does not configure: a three-server fallback is too little to
# ship silently, and the released Arch and OpenWrt packages have both baked
# it that way without anyone noticing. The fallback stays available behind
# an explicit switch for builds that truly cannot fetch the list.
option(COMRADE_STUN_FALLBACK "Bake a minimal STUN fallback when the always-online-stun submodule is absent" OFF)
set(STUN_LIST_SRC "${CMAKE_CURRENT_SOURCE_DIR}/deps/always-online-stun/valid_nat_testing_hosts.txt")
set(STUN_BUNDLE_INC "${CMAKE_CURRENT_BINARY_DIR}/stun_bundle.inc")
if(EXISTS "${STUN_LIST_SRC}")
	file(STRINGS "${STUN_LIST_SRC}" STUN_LIST_LINES)
elseif(COMRADE_STUN_FALLBACK)
	message(WARNING "always-online-stun submodule not present; baking the minimal STUN fallback (COMRADE_STUN_FALLBACK=ON)")
	set(STUN_LIST_LINES "stun.nextcloud.com:443" "stun.sipgate.net:3478" "stun.ipfire.org:3478")
else()
	message(FATAL_ERROR
		"The STUN server pool is missing: deps/always-online-stun has no "
		"valid_nat_testing_hosts.txt. Run\n"
		"   git submodule update --init --depth 1 deps/always-online-stun\n"
		"or place the pinned list there yourself (as the OpenWrt package "
		"does), or pass -DCOMRADE_STUN_FALLBACK=ON to knowingly bake a "
		"three-server fallback.")
endif()
# Anti-big-tech filter: drop servers whose hostname matches a blocklist entry
# (operators and cloud/CDN hosting of hyperscalers). Applied to the baked pool
# only; `comrade stun-update` fetches the raw upstream list and warns instead.
set(STUN_BLOCKLIST_FILE "${CMAKE_CURRENT_SOURCE_DIR}/stun_blocklist.txt")
set(STUN_BLOCK_PATTERNS "")
if(EXISTS "${STUN_BLOCKLIST_FILE}")
	file(STRINGS "${STUN_BLOCKLIST_FILE}" _bl)
	foreach(_p ${_bl})
		string(STRIP "${_p}" _p)
		if(_p AND NOT _p MATCHES "^#")
			string(TOLOWER "${_p}" _p)
			list(APPEND STUN_BLOCK_PATTERNS "${_p}")
		endif()
	endforeach()
endif()
set(STUN_BUNDLE_BODY "/* Generated from always-online-stun; do not edit. */\nstatic const char *const stun_bundle[] = {\n")
set(STUN_KEPT 0)
set(STUN_DROPPED 0)
foreach(_line ${STUN_LIST_LINES})
	string(STRIP "${_line}" _line)
	if(_line MATCHES "^[A-Za-z0-9]")
		string(TOLOWER "${_line}" _lc)
		set(_blocked FALSE)
		foreach(_p ${STUN_BLOCK_PATTERNS})
			string(FIND "${_lc}" "${_p}" _idx)
			if(NOT _idx EQUAL -1)
				set(_blocked TRUE)
				break()
			endif()
		endforeach()
		if(_blocked)
			math(EXPR STUN_DROPPED "${STUN_DROPPED} + 1")
		else()
			string(APPEND STUN_BUNDLE_BODY "\t\"${_line}\",\n")
			math(EXPR STUN_KEPT "${STUN_KEPT} + 1")
		endif()
	endif()
endforeach()
string(APPEND STUN_BUNDLE_BODY "};\n")
file(WRITE "${STUN_BUNDLE_INC}" "${STUN_BUNDLE_BODY}")
message(STATUS "STUN bundle: ${STUN_KEPT} servers baked, ${STUN_DROPPED} big-tech dropped")

add_library(comrade_stunlist STATIC src/stunlist.c)
target_include_directories(comrade_stunlist PUBLIC src PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(comrade_stunlist PUBLIC comrade_appdir)

set(COMRADE_CRYPTO_SRC src/sha1.c src/bencode.c src/keys.c src/netmon.c src/candpolicy.c src/candpack.c)
if(COMRADE_CRYPTO_RESOLVED STREQUAL "monocypher")
	add_library(comrade_crypto STATIC ${COMRADE_CRYPTO_SRC} src/ccrypto_monocypher.c)
	target_include_directories(comrade_crypto PUBLIC src)
	target_link_libraries(comrade_crypto PUBLIC comrade_compat)
	if(TARGET PkgConfig::MONOCYPHER)
		target_link_libraries(comrade_crypto PUBLIC PkgConfig::MONOCYPHER)
	else()
		target_include_directories(comrade_crypto PUBLIC ${MONOCYPHER_INCLUDE_DIR})
		target_link_libraries(comrade_crypto PUBLIC ${MONOCYPHER_LIBRARY})
	endif()
elseif(COMRADE_CRYPTO_RESOLVED STREQUAL "gcrypt")
	add_library(comrade_crypto STATIC ${COMRADE_CRYPTO_SRC} src/ccrypto_gcrypt.c)
	target_include_directories(comrade_crypto PUBLIC src)
	target_link_libraries(comrade_crypto PUBLIC Threads::Threads comrade_compat)
	if(TARGET PkgConfig::GCRYPT)
		target_link_libraries(comrade_crypto PUBLIC PkgConfig::GCRYPT)
	else()
		target_include_directories(comrade_crypto PUBLIC ${GCRYPT_INCLUDE_DIR})
		target_link_libraries(comrade_crypto PUBLIC ${GCRYPT_LIBRARY})
	endif()
else()
	add_library(comrade_crypto STATIC ${COMRADE_CRYPTO_SRC} src/ccrypto_openssl.c)
	target_include_directories(comrade_crypto PUBLIC src)
	target_link_libraries(comrade_crypto PUBLIC OpenSSL::Crypto comrade_compat)
endif()

# The rendezvous mailbox: the two-slot container plus turnstile claim logic
# (bencode only, no crypto or DHT), extracted from sig.c so it is unit-testable.
add_library(comrade_mailbox STATIC src/mailbox.c)
target_include_directories(comrade_mailbox PUBLIC src)
target_link_libraries(comrade_mailbox PUBLIC comrade_crypto)

#
# jech/dht comes either as a plain source checkout (-DCOMRADE_DHT_DIR, which
# compiles dht.c straight in) or as an installed shared library, which is
# preferred when no checkout is given: distributions package it (OpenWrt's
# libdht, which transmission already links), and comrade is an ordinary
# consumer of it. Nothing about the callback design forces the source route --
# comrade calls only dht.h's public API and defines the four symbols the
# library deliberately leaves undefined (dht_hash, dht_random_bytes,
# dht_blacklisted, dht_sendto), which the dynamic linker resolves back into
# the executable. (Both are located up with the dependency summary.)
#

# BEP 44 is a self-contained engine: it speaks the mainline protocol over a
# socket the caller owns and makes no call into jech/dht, so it is its own
# target and consumers that only want put/get (bep44_test) never drag in the
# DHT library.
add_library(comrade_bep44 STATIC src/bep44.c)
target_include_directories(comrade_bep44 PUBLIC src)
target_link_libraries(comrade_bep44 PUBLIC comrade_crypto comrade_compat)

# The check above guarantees one of the two jech/dht routes is present: a
# source checkout compiled straight in, or an installed libdht to link.
if(COMRADE_DHT_DIR AND EXISTS "${COMRADE_DHT_DIR}/dht.c")
	set(COMRADE_DHT_HOW "dht.c compiled in from ${COMRADE_DHT_DIR}")
	add_library(comrade_dht STATIC ${COMRADE_DHT_DIR}/dht.c src/dhtnode.c)
	target_include_directories(comrade_dht PUBLIC src ${COMRADE_DHT_DIR})
	set_source_files_properties(${COMRADE_DHT_DIR}/dht.c PROPERTIES
		COMPILE_OPTIONS "-w")
else()
	set(COMRADE_DHT_HOW "linking ${COMRADE_DHT_LIBRARY}")
	# dhtnode.c both drives libdht and defines the four callbacks it leaves
	# undefined, so any target that links the library also pulls those in.
	add_library(comrade_dht STATIC src/dhtnode.c)
	target_include_directories(comrade_dht PUBLIC src ${COMRADE_DHT_INCLUDE_DIR})
	target_link_libraries(comrade_dht PUBLIC ${COMRADE_DHT_LIBRARY})
endif()
target_compile_definitions(comrade_dht PRIVATE _GNU_SOURCE)
target_link_libraries(comrade_dht PUBLIC comrade_bep44 comrade_crypto
	comrade_appdir comrade_compat Threads::Threads)
message(STATUS "DHT: ${COMRADE_DHT_HOW}")

add_library(comrade_sig STATIC src/sig.c src/sig_mcast.c)
target_include_directories(comrade_sig PUBLIC src)
target_link_libraries(comrade_sig PUBLIC comrade_dht comrade_mailbox
	comrade_dbg comrade_compat)

add_library(comrade_nat STATIC src/nat.c)
target_include_directories(comrade_nat PUBLIC src)
target_link_libraries(comrade_nat PUBLIC LibJuice::LibJuice)

add_library(comrade_stunprobe STATIC src/stunprobe.c)
target_include_directories(comrade_stunprobe PUBLIC src)
target_link_libraries(comrade_stunprobe PUBLIC comrade_compat)

add_library(comrade_path STATIC src/path.c)
target_include_directories(comrade_path PUBLIC src)
target_link_libraries(comrade_path PUBLIC comrade_crypto comrade_compat)

add_library(comrade_lanlink STATIC src/lanlink.c)
target_include_directories(comrade_lanlink PUBLIC src)
target_link_libraries(comrade_lanlink PUBLIC comrade_compat)

# kcp >= 2.1 has pluggable congestion control (ikcp_setcc); the rate-based
# controller in stream.c needs it. Probe rather than pin, so an older kcp
# still builds -- it just keeps kcp's builtin controller.
include(CheckSymbolExists)
get_target_property(COMRADE_KCP_INCLUDES kcp::kcp INTERFACE_INCLUDE_DIRECTORIES)
set(CMAKE_REQUIRED_INCLUDES ${COMRADE_KCP_INCLUDES})
set(CMAKE_REQUIRED_LIBRARIES kcp::kcp)
check_symbol_exists(ikcp_setcc "ikcp.h" COMRADE_HAVE_KCP_CC)
unset(CMAKE_REQUIRED_INCLUDES)
unset(CMAKE_REQUIRED_LIBRARIES)

add_library(comrade_stream STATIC src/stream.c)
if(COMRADE_HAVE_KCP_CC)
	target_compile_definitions(comrade_stream PRIVATE COMRADE_HAVE_KCP_CC=1)
endif()
target_include_directories(comrade_stream PUBLIC src)
target_link_libraries(comrade_stream PUBLIC kcp::kcp Threads::Threads)

add_library(comrade_bridge STATIC src/sshbridge.c)
target_include_directories(comrade_bridge PUBLIC src)
target_link_libraries(comrade_bridge PUBLIC comrade_stream comrade_compat)

# ssh_pki_generate_key() replaced the (now deprecated) ssh_pki_generate()
# in a recent libssh; Debian stable and Ubuntu LTS still ship the older
# one. Probe rather than pin a version, so both build.
include(CheckSymbolExists)
set(CMAKE_REQUIRED_INCLUDES ${LIBSSH_INCLUDE_DIRS})
set(CMAKE_REQUIRED_LIBRARIES ${LIBSSH_LIBRARIES})
if(WIN32)
	# The probe links for real, so it needs the same static-libssh
	# treatment the build does: LIBSSH_STATIC (or the symbol resolves
	# to __imp_ssh_pki_generate_key) and libssh's crypto backend.
	set(CMAKE_REQUIRED_DEFINITIONS -DLIBSSH_STATIC)
	list(APPEND CMAKE_REQUIRED_LIBRARIES ${COMRADE_WIN_LIBS})
	list(APPEND CMAKE_REQUIRED_LINK_OPTIONS ${COMRADE_WIN_LINK})
endif()
check_symbol_exists(ssh_pki_generate_key "libssh/libssh.h"
	COMRADE_HAVE_PKI_GENERATE_KEY)
unset(CMAKE_REQUIRED_INCLUDES)
unset(CMAKE_REQUIRED_LIBRARIES)
unset(CMAKE_REQUIRED_DEFINITIONS)
unset(CMAKE_REQUIRED_LINK_OPTIONS)
add_library(comrade_ssh STATIC src/sshd.c src/sshc.c src/sshfwd.c)
if(COMRADE_HAVE_PKI_GENERATE_KEY)
	target_compile_definitions(comrade_ssh
		PRIVATE COMRADE_HAVE_PKI_GENERATE_KEY=1)
endif()
target_include_directories(comrade_ssh PUBLIC src)
# The message-based libssh server API is deprecated in favour of the
# callback API but is clearer and fully functional; migrate later.
target_compile_options(comrade_ssh PRIVATE -Wno-deprecated-declarations)
target_link_libraries(comrade_ssh PUBLIC comrade_token comrade_statusbar comrade_dbg comrade_termfilter comrade_fwdspec comrade_compat comrade_cpty PkgConfig::LIBSSH Threads::Threads)
find_library(COMRADE_UTIL util)
if(COMRADE_UTIL)
	target_link_libraries(comrade_ssh PUBLIC ${COMRADE_UTIL})
endif()

add_library(comrade_session STATIC src/session.c)
target_include_directories(comrade_session PUBLIC src)
target_link_libraries(comrade_session PUBLIC
	comrade_sig comrade_nat comrade_lanlink comrade_stream comrade_ssh
	comrade_bridge comrade_token comrade_crypto comrade_stunlist
	comrade_stunprobe comrade_conn comrade_path comrade_ctlproto comrade_dbg
	comrade_netstate comrade_nsfacts comrade_hostreap comrade_claimlog
	comrade_hbeat comrade_replay comrade_dataauth)

# The view: the only module that draws to the terminal (MVC).
# Token QR codes for the dashboard. qrcodegen.c is vendored from Project
# Nayuki's QR Code generator library (MIT), like the vendored jech/dht kept
# out of the warning bar.
add_library(comrade_qr STATIC src/qr.c src/qrcodegen.c)
target_include_directories(comrade_qr PUBLIC src)
set_source_files_properties(src/qrcodegen.c PROPERTIES COMPILE_OPTIONS -w)

add_library(comrade_ui STATIC src/ui.c)
target_include_directories(comrade_ui PUBLIC src)
target_link_libraries(comrade_ui PUBLIC comrade_token comrade_qr comrade_compat)

# The host, in two files: the POSIX one and the Windows one. Each is guarded
# so exactly one of them defines host_run/host_show, which keeps both readable
# -- the alternative was an #ifdef through every function in host.c, since
# almost every line of it is a fork, a pty or a signal.
add_library(comrade_host STATIC src/host.c src/host_win.c src/showfmt.c
	src/mview.c)
target_include_directories(comrade_host PUBLIC src)
target_link_libraries(comrade_host PUBLIC comrade_token comrade_dbg comrade_termfilter
	comrade_session comrade_ui)
if(WIN32)
	# host_win.c serialises the ephemeral host key to the detached
	# service over their socketpair, so it talks to libssh directly.
	target_link_libraries(comrade_host PUBLIC comrade_cpty
		comrade_statusbar comrade_conn PkgConfig::LIBSSH)
endif()

# --- build identity (comrade --version) --------------------------------------
# The commit hash, date and, on a tagged build, the release version are baked
# into the binary. In a git checkout these come from git; a `git archive` source
# tarball carries no .git, so src/gitident.txt holds $Format:...$ placeholders
# that git expands at archive time (see .gitattributes). One path serves both.
set(COMRADE_GIT_HASH "unknown")
set(COMRADE_GIT_DATE "unknown")
set(_cr_refs "")
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/src/gitident.txt" _cr_ident)
string(REGEX MATCH "COMRADE_GIT_HASH=([^\r\n]*)" _cr_m "${_cr_ident}")
set(_cr_hash "${CMAKE_MATCH_1}")
if(_cr_hash MATCHES "Format:")
	# Working tree (placeholders unexpanded): ask git. -c safe.directory keeps
	# it working on a foreign-owned tree, e.g. the deb build container.
	find_package(Git QUIET)
	if(GIT_FOUND)
		set(_cr_git ${GIT_EXECUTABLE}
			-c safe.directory=${CMAKE_CURRENT_SOURCE_DIR}
			-C ${CMAKE_CURRENT_SOURCE_DIR})
		execute_process(COMMAND ${_cr_git} rev-parse HEAD
			OUTPUT_VARIABLE COMRADE_GIT_HASH
			OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
		execute_process(COMMAND ${_cr_git} show -s --format=%cs HEAD
			OUTPUT_VARIABLE COMRADE_GIT_DATE
			OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
		execute_process(COMMAND ${_cr_git} log -1 --format=%D HEAD
			OUTPUT_VARIABLE _cr_refs
			OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
		# What git said is true of the commit that was checked out when
		# this ran, and nothing re-runs it on its own: without these a
		# tree that has moved on since keeps reporting the commit it was
		# configured at, which is the one identity a binary should never
		# get wrong. A worktree or submodule keeps .git as a file rather
		# than a directory, and then there is nothing here to watch.
		set(_cr_head "${CMAKE_CURRENT_SOURCE_DIR}/.git/HEAD")
		if(EXISTS "${_cr_head}")
			set_property(DIRECTORY APPEND PROPERTY
				CMAKE_CONFIGURE_DEPENDS "${_cr_head}")
			file(READ "${_cr_head}" _cr_headtxt)
			string(REGEX MATCH "ref: ([^\r\n]+)" _cr_m
				"${_cr_headtxt}")
			set(_cr_ref
				"${CMAKE_CURRENT_SOURCE_DIR}/.git/${CMAKE_MATCH_1}")
			if(CMAKE_MATCH_1 AND EXISTS "${_cr_ref}")
				set_property(DIRECTORY APPEND PROPERTY
					CMAKE_CONFIGURE_DEPENDS "${_cr_ref}")
			endif()
		endif()
	endif()
else()
	# Expanded by `git archive`: trust the baked-in identity, no git needed.
	set(COMRADE_GIT_HASH "${_cr_hash}")
	if(_cr_ident MATCHES "COMRADE_GIT_DATE=([^\r\n]*)")
		set(COMRADE_GIT_DATE "${CMAKE_MATCH_1}")
	endif()
	if(_cr_ident MATCHES "COMRADE_GIT_REFS=([^\r\n]*)")
		set(_cr_refs "${CMAKE_MATCH_1}")
	endif()
	if(_cr_refs MATCHES "Format:")
		set(_cr_refs "")
	endif()
endif()
if(COMRADE_GIT_HASH STREQUAL "")
	set(COMRADE_GIT_HASH "unknown")
endif()
if(COMRADE_GIT_DATE STREQUAL "")
	set(COMRADE_GIT_DATE "unknown")
endif()
if(NOT COMRADE_GIT_HASH STREQUAL "unknown")
	string(SUBSTRING "${COMRADE_GIT_HASH}" 0 12 COMRADE_GIT_HASH)
endif()
# A release is a commit an exact tag points at: a "tag: <name>" ref decoration
# (%D). Reliable in a `git archive` tarball, unlike %(describe) which servers
# such as GitHub may not expand.
set(COMRADE_RELEASE "")
if(_cr_refs MATCHES "tag: ([^,\r\n]+)")
	string(STRIP "${CMAKE_MATCH_1}" _cr_tag)
	string(REGEX REPLACE "^v" "" COMRADE_RELEASE "${_cr_tag}")
endif()
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/src/version.h.in"
	"${CMAKE_CURRENT_BINARY_DIR}/version.h" @ONLY)

add_executable(comrade src/main.c)
target_include_directories(comrade PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(comrade
	comrade_host
	comrade_session
	comrade_ui
	comrade_token
	comrade_stunlist
	comrade_statusbar
	comrade_fwdspec
)
if(WIN32)
	# The system import libraries go last so they resolve the references the
	# static archives above leave open, and -static keeps libgcc and
	# winpthreads inside the image.
	target_link_libraries(comrade ${COMRADE_WIN_LIBS})
	target_link_options(comrade PRIVATE ${COMRADE_WIN_LINK})
endif()

install(TARGETS comrade RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

if(BUILD_TESTING)
	add_executable(token_test tests/token_test.c)
	target_link_libraries(token_test comrade_token)
	add_test(NAME token_test COMMAND token_test)

	# qr_test includes qr.c for its statics; the archive still supplies
	# qrcodegen.
	add_executable(qr_test tests/qr_test.c)
	target_link_libraries(qr_test comrade_qr)
	add_test(NAME qr_test COMMAND qr_test)

	add_executable(showfmt_test tests/showfmt_test.c src/showfmt.c)
	target_link_libraries(showfmt_test comrade_token comrade_compat)
	add_test(NAME showfmt_test COMMAND showfmt_test)

	# Writes its status file through mkstemp under /tmp, which is the one
	# POSIX thing about it.
	if(UNIX)
		add_executable(mview_test tests/mview_test.c src/mview.c src/showfmt.c)
		target_link_libraries(mview_test comrade_token comrade_compat)
		add_test(NAME mview_test COMMAND mview_test)
	endif()

	add_executable(tokgen_test tests/tokgen_test.c)
	target_link_libraries(tokgen_test comrade_token)
	add_test(NAME tokgen_test COMMAND tokgen_test)

	add_executable(netstate_test tests/netstate_test.c)
	target_link_libraries(netstate_test comrade_netstate)
	add_test(NAME netstate_test COMMAND netstate_test)

	add_executable(nsfacts_test tests/nsfacts_test.c)
	target_link_libraries(nsfacts_test comrade_nsfacts)
	add_test(NAME nsfacts_test COMMAND nsfacts_test)

	# When a worker gives up on the client it serves, against a clock the
	# test hands it rather than a live host and a real outage.
	add_executable(hostreap_test tests/hostreap_test.c)
	target_link_libraries(hostreap_test comrade_hostreap)
	add_test(NAME hostreap_test COMMAND hostreap_test)

	# When the signaller is given up on: the node's own view of its table,
	# and the backstop for a table that looks fine and answers nothing.
	add_executable(sigquiet_test tests/sigquiet_test.c)
	target_link_libraries(sigquiet_test comrade_sig)
	add_test(NAME sigquiet_test COMMAND sigquiet_test)

	# Telling a claim the DHT is handing back from a claimant trying again.
	add_executable(claimlog_test tests/claimlog_test.c)
	target_link_libraries(claimlog_test comrade_claimlog)
	add_test(NAME claimlog_test COMMAND claimlog_test)

	# How long silence may last before a link is given up on.
	add_executable(hbeat_test tests/hbeat_test.c)
	target_link_libraries(hbeat_test comrade_hbeat)
	add_test(NAME hbeat_test COMMAND hbeat_test)

	# One frame acted on once: the sliding window over a peer's sequence.
	add_executable(replay_test tests/replay_test.c)
	target_link_libraries(replay_test comrade_replay)
	add_test(NAME replay_test COMMAND replay_test)

	add_executable(termfilter_test tests/termfilter_test.c)
	target_link_libraries(termfilter_test comrade_termfilter)
	add_test(NAME termfilter_test COMMAND termfilter_test)

	add_executable(ctlproto_test tests/ctlproto_test.c)
	target_link_libraries(ctlproto_test comrade_ctlproto)
	add_test(NAME ctlproto_test COMMAND ctlproto_test)

	add_executable(netmon_test tests/netmon_test.c)
	target_link_libraries(netmon_test comrade_crypto)
	add_test(NAME netmon_test COMMAND netmon_test)

	add_executable(path_test tests/path_test.c)
	target_link_libraries(path_test comrade_path)
	add_test(NAME path_test COMMAND path_test)

	add_executable(candpolicy_test tests/candpolicy_test.c)
	target_link_libraries(candpolicy_test comrade_crypto comrade_path)
	add_test(NAME candpolicy_test COMMAND candpolicy_test)

	add_executable(stunprobe_test tests/stunprobe_test.c)
	target_link_libraries(stunprobe_test comrade_stunprobe)
	add_test(NAME stunprobe_test COMMAND stunprobe_test)

	add_executable(candpack_test tests/candpack_test.c)
	target_link_libraries(candpack_test comrade_crypto)
	add_test(NAME candpack_test COMMAND candpack_test)

	add_executable(mailbox_test tests/mailbox_test.c)
	target_link_libraries(mailbox_test comrade_mailbox)
	add_test(NAME mailbox_test COMMAND mailbox_test)

	add_executable(roauth_test tests/roauth_test.c)
	target_link_libraries(roauth_test comrade_crypto comrade_token)
	add_test(NAME roauth_test COMMAND roauth_test)

	add_executable(connkey_test tests/connkey_test.c)
	target_link_libraries(connkey_test comrade_crypto comrade_token)
	add_test(NAME connkey_test COMMAND connkey_test)

	add_executable(dataauth_test tests/dataauth_test.c)
	target_link_libraries(dataauth_test comrade_dataauth)
	add_test(NAME dataauth_test COMMAND dataauth_test)

	add_executable(box_test tests/box_test.c)
	target_link_libraries(box_test comrade_crypto comrade_token)
	add_test(NAME box_test COMMAND box_test)

	# Both exercise the BEP 44 engine alone, which needs no DHT library.
	add_executable(bep44_test tests/bep44_test.c)
	target_link_libraries(bep44_test comrade_bep44)
	add_test(NAME bep44_test COMMAND bep44_test)

	if(UNIX)
		add_executable(bep44_pin_test tests/bep44_pin_test.c)
		target_link_libraries(bep44_pin_test comrade_bep44)
		add_test(NAME bep44_pin_test COMMAND bep44_pin_test)
		set_tests_properties(bep44_pin_test PROPERTIES TIMEOUT 15)
	endif()

	# The storing side, driven the way the network drives it: crafted
	# datagrams in, replies read back off a loopback socket.
	if(UNIX)
		add_executable(bep44_store_test tests/bep44_store_test.c)
		target_link_libraries(bep44_store_test comrade_bep44)
		add_test(NAME bep44_store_test COMMAND bep44_store_test)
		set_tests_properties(bep44_store_test PROPERTIES TIMEOUT 120)
	endif()

	# Includes bep44.c to reach the static per-source rate bucket, so it
	# links the crypto pieces directly rather than the comrade_bep44 archive.
	add_executable(bep44_rl_test tests/bep44_rl_test.c)
	target_link_libraries(bep44_rl_test comrade_crypto comrade_compat)
	target_include_directories(bep44_rl_test PRIVATE src)
	add_test(NAME bep44_rl_test COMMAND bep44_rl_test)

	# Creates and tears down real DHT nodes (two UDP sockets on the wildcard
	# address, nothing sent) and stalls their bootstrap resolve, so it needs
	# no network; SKIPs (77) where no socket can be had. XDG_DATA_HOME keeps
	# the node cache it persists out of the developer's data dir.
	# Stalls the bootstrap by defining getaddrinfo over the C library's,
	# which is a POSIX linker's behaviour; the Windows one refuses it.
	if(UNIX)
		add_executable(sig_rebuild_test tests/sig_rebuild_test.c)
		target_link_libraries(sig_rebuild_test comrade_sig)
		add_test(NAME sig_rebuild_test COMMAND sig_rebuild_test)
		set_tests_properties(sig_rebuild_test PROPERTIES
			SKIP_RETURN_CODE 77 TIMEOUT 30
			ENVIRONMENT XDG_DATA_HOME=${CMAKE_CURRENT_BINARY_DIR}/test-data)
	endif()

	add_executable(natstream_test tests/natstream_test.c)
	target_link_libraries(natstream_test comrade_nat comrade_stream)
	add_test(NAME natstream_test COMMAND natstream_test)
	set_tests_properties(natstream_test PROPERTIES TIMEOUT 60)

	add_executable(stream_room_test tests/stream_room_test.c)
	target_link_libraries(stream_room_test comrade_stream)
	add_test(NAME stream_room_test COMMAND stream_room_test)
	set_tests_properties(stream_room_test PROPERTIES TIMEOUT 30)

	if(COMRADE_HAVE_KCP_CC)
		add_executable(stream_cc_test tests/stream_cc_test.c)
		target_link_libraries(stream_cc_test comrade_stream)
		add_test(NAME stream_cc_test COMMAND stream_cc_test)
		set_tests_properties(stream_cc_test PROPERTIES TIMEOUT 60)
	endif()

	# The bridge tests plumb a session over a socketpair and drive it from
	# threads, which is POSIX and not the library's own portability layer.
	if(UNIX)
		add_executable(sshloop_test tests/sshloop_test.c)
		target_link_libraries(sshloop_test comrade_ssh comrade_token Threads::Threads)
		add_test(NAME sshloop_test COMMAND sshloop_test)
		set_tests_properties(sshloop_test PROPERTIES TIMEOUT 30)

		add_executable(sshfwd_test tests/sshfwd_test.c)
		target_link_libraries(sshfwd_test comrade_ssh comrade_token Threads::Threads)
		add_test(NAME sshfwd_test COMMAND sshfwd_test)
		set_tests_properties(sshfwd_test PROPERTIES TIMEOUT 60)

		add_executable(sshexit_test tests/sshexit_test.c)
		target_link_libraries(sshexit_test comrade_ssh comrade_token Threads::Threads)
		add_test(NAME sshexit_test COMMAND sshexit_test)
		set_tests_properties(sshexit_test PROPERTIES TIMEOUT 30)

		add_executable(sshro_test tests/sshro_test.c)
		target_link_libraries(sshro_test
			comrade_ssh comrade_crypto comrade_token Threads::Threads)
		add_test(NAME sshro_test COMMAND sshro_test)
		set_tests_properties(sshro_test PROPERTIES TIMEOUT 30)

		add_executable(sshkcp_test tests/sshkcp_test.c)
		target_link_libraries(sshkcp_test
			comrade_ssh comrade_bridge comrade_stream comrade_token Threads::Threads)
		add_test(NAME sshkcp_test COMMAND sshkcp_test)
		add_executable(sshctl_test tests/sshctl_test.c)
		target_link_libraries(sshctl_test comrade_ssh comrade_bridge comrade_stream comrade_token Threads::Threads)
		add_test(NAME sshctl_test COMMAND sshctl_test)
		set_tests_properties(sshkcp_test PROPERTIES TIMEOUT 30)
	endif()

	# What the e2e scripts print when they fail goes through a filter first
	# (tests/redact.sh), since a workflow run publishes that output. Plain
	# shell and no network, so it runs in every build rather than with the
	# e2e tests it serves.
	if(UNIX)
		add_test(NAME redact_test
			COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/redact_test.sh)
		set_tests_properties(redact_test PROPERTIES TIMEOUT 30)
	endif()
endif()

if(COMRADE_BUILD_TOOLS)
	add_executable(comrade-sigprobe tools/sigprobe.c)
	target_link_libraries(comrade-sigprobe comrade_dht comrade_token)
	# One node of the private DHT the network tests run against.
	add_executable(comrade-dhtseed tools/dhtseed.c)
	target_link_libraries(comrade-dhtseed comrade_dht)

	add_executable(comrade-rdvbench tools/rdvbench.c)
	target_link_libraries(comrade-rdvbench comrade_dht comrade_token)

	add_executable(comrade-e2e tools/e2e.c)
	target_link_libraries(comrade-e2e comrade_session)
	if(COMRADE_STATIC)
		target_link_options(comrade-e2e PRIVATE -static)
	endif()

	# Concurrent multi-user e2e: one host, N clients racing the turnstile over
	# the live DHT. Skipped unless COMRADE_E2E_NET=1 (see tests/multiuser.sh),
	# so the offline suite is unaffected; the turnstile's race-freedom is
	# proven deterministically by mailbox_test.
	if(BUILD_TESTING AND UNIX)
		# One swarm for the whole run rather than eight nodes per test:
		# building them answers the same question every time, and the few
		# seconds it takes are paid by every DHT-gated test below. A test
		# whose fixture did not run builds its own, exactly as before, so
		# nothing here is load-bearing.
		set(COMRADE_SWARM_FILE ${CMAKE_CURRENT_BINARY_DIR}/swarm.boot)
		add_test(NAME swarm_up
			COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/swarmfix.sh
				$<TARGET_FILE:comrade-dhtseed> up)
		set_tests_properties(swarm_up PROPERTIES
			FIXTURES_SETUP swarm SKIP_RETURN_CODE 77 TIMEOUT 120
			ENVIRONMENT COMRADE_SWARM_FILE=${COMRADE_SWARM_FILE})
		add_test(NAME swarm_down
			COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/swarmfix.sh
				$<TARGET_FILE:comrade-dhtseed> down)
		set_tests_properties(swarm_down PROPERTIES
			FIXTURES_CLEANUP swarm TIMEOUT 60
			ENVIRONMENT COMRADE_SWARM_FILE=${COMRADE_SWARM_FILE})

		# Port forwarding over a real path, both arrangements that work.
		add_test(NAME forward_e2e
			COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/forward.sh
				$<TARGET_FILE:comrade>
				$<TARGET_FILE:comrade-dhtseed>)
		set_tests_properties(forward_e2e PROPERTIES
			SKIP_RETURN_CODE 77 TIMEOUT 180
			FIXTURES_REQUIRED swarm
			ENVIRONMENT COMRADE_SWARM_FILE=${COMRADE_SWARM_FILE})

		add_test(NAME multiuser_e2e
			COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/multiuser.sh
				$<TARGET_FILE:comrade-e2e>
				$<TARGET_FILE:comrade-dhtseed> 2)
		set_tests_properties(multiuser_e2e PROPERTIES
			SKIP_RETURN_CODE 77 TIMEOUT 180
			FIXTURES_REQUIRED swarm
			ENVIRONMENT COMRADE_SWARM_FILE=${COMRADE_SWARM_FILE})

		# Isolated-LAN token mint + connect over real multicast on this host
		# Needs no DHT and no network beyond one up
		# multicast interface; SKIPs (77) when none exists.
		add_test(NAME isolated_lan_e2e
			COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/isolated_lan.sh
				$<TARGET_FILE:comrade-e2e>)
		set_tests_properties(isolated_lan_e2e PROPERTIES
			SKIP_RETURN_CODE 77 TIMEOUT 90)

		# Concurrent isolated-LAN admission: N clients join one no-DHT host at
		# once over multicast. Offline and
		# deterministic; SKIPs (77) with no multicast interface.
		add_test(NAME lan_concurrent_e2e
			COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/lan_concurrent.sh
				$<TARGET_FILE:comrade-e2e> 4)
		set_tests_properties(lan_concurrent_e2e PROPERTIES
			SKIP_RETURN_CODE 77 TIMEOUT 120)

		# Mixed lanlink + DHT/ICE peers in one session: a
		# lanlink worker and an ICE worker must coexist live. Needs the live
		# DHT, so SKIPs (77) unless COMRADE_E2E_NET=1.
		add_test(NAME lan_mixed_e2e
			COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/lan_mixed.sh
				$<TARGET_FILE:comrade-e2e>
				$<TARGET_FILE:comrade-dhtseed>)
		set_tests_properties(lan_mixed_e2e PROPERTIES
			SKIP_RETURN_CODE 77 TIMEOUT 180
			FIXTURES_REQUIRED swarm
			ENVIRONMENT COMRADE_SWARM_FILE=${COMRADE_SWARM_FILE})

		# Release-on-pickup: a wedged ICE punch must not head-of-line-block the
		# next joiner. The wedge is host-controlled
		# (deterministic); the joiners use the live DHT, so SKIPs (77) unless
		# COMRADE_E2E_NET=1. Passes only when release-on-pickup works.
		add_test(NAME turnstile_stuck_e2e
			COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/turnstile_stuck.sh
				$<TARGET_FILE:comrade-e2e>
				$<TARGET_FILE:comrade-dhtseed>)
		set_tests_properties(turnstile_stuck_e2e PROPERTIES
			SKIP_RETURN_CODE 77 TIMEOUT 180
			FIXTURES_REQUIRED swarm
			ENVIRONMENT COMRADE_SWARM_FILE=${COMRADE_SWARM_FILE})

		# The host turnstile rebuilds its signalling on a move while its
		# workers keep serving, the move manufactured by --roam-ms. No
		# DHT, so it is offline and deterministic; SKIPs (77) with no
		# multicast interface.
		add_test(NAME roam_lan_e2e
			COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/roam.sh
				$<TARGET_FILE:comrade-e2e>)
		set_tests_properties(roam_lan_e2e PROPERTIES
			SKIP_RETURN_CODE 77 TIMEOUT 120)

		# One family moving is not the other one moving: a v6-only
		# renumbering must leave v4's facts standing. Offline, same
		# multicast requirement.
		add_test(NAME roam_fam_e2e
			COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/roam_fam.sh
				$<TARGET_FILE:comrade-e2e>)
		set_tests_properties(roam_fam_e2e PROPERTIES
			SKIP_RETURN_CODE 77 TIMEOUT 90)

		# The client half of the same handler: a client that rebuilds
		# while still looking must still join over what it rebuilt. Its
		# rendezvous is the DHT, so SKIPs (77) unless COMRADE_E2E_NET=1.
		add_test(NAME roam_client_e2e
			COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/roam_client.sh
				$<TARGET_FILE:comrade-e2e>
				$<TARGET_FILE:comrade-dhtseed>)
		set_tests_properties(roam_client_e2e PROPERTIES
			SKIP_RETURN_CODE 77 TIMEOUT 180
			FIXTURES_REQUIRED swarm
			ENVIRONMENT COMRADE_SWARM_FILE=${COMRADE_SWARM_FILE})

		# A roam as a path switch rather than a rejoin: the path
		# carrying the session is taken away (--blackhole-ms) and the
		# session must move to another warm one intact. No DHT, so it is
		# offline; SKIPs (77) with no multicast interface, or where this
		# host has only one path to offer.
		add_test(NAME path_switch_e2e
			COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/path_switch.sh
				$<TARGET_FILE:comrade-e2e>)
		set_tests_properties(path_switch_e2e PROPERTIES
			SKIP_RETURN_CODE 77 TIMEOUT 120)

		# A total outage mid-session resumes in place: same worker,
		# same SSH session, the punch grafted. Its rendezvous is the
		# DHT, so SKIPs (77) unless COMRADE_E2E_NET=1.
		add_test(NAME resume_e2e
			COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/resume.sh
				$<TARGET_FILE:comrade-e2e>
				$<TARGET_FILE:comrade-dhtseed>)
		set_tests_properties(resume_e2e PROPERTIES
			SKIP_RETURN_CODE 77 TIMEOUT 180
			FIXTURES_REQUIRED swarm
			ENVIRONMENT COMRADE_SWARM_FILE=${COMRADE_SWARM_FILE})

		# The same reap on a segment: no ICE agent to be told on, and a
		# segment path is what roaming ends.
		add_test(NAME rejoin_lan_e2e
			COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/rejoin_lan.sh
				$<TARGET_FILE:comrade-e2e>)
		set_tests_properties(rejoin_lan_e2e PROPERTIES
			SKIP_RETURN_CODE 77 TIMEOUT 180)

		# The outage the worker does not survive: nothing to resume
		# into, so the client has to come back as a fresh one.
		add_test(NAME rejoin_e2e
			COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/rejoin.sh
				$<TARGET_FILE:comrade-e2e>
				$<TARGET_FILE:comrade-dhtseed>)
		set_tests_properties(rejoin_e2e PROPERTIES
			SKIP_RETURN_CODE 77 TIMEOUT 200
			FIXTURES_REQUIRED swarm
			ENVIRONMENT COMRADE_SWARM_FILE=${COMRADE_SWARM_FILE})

		# The HOST roams mid-session (sig rebuilt, offer rotated, old
		# transport silenced); the client resumes in place against the
		# rotated offer. DHT rendezvous, so SKIPs without the net gate.
		add_test(NAME hostroam_e2e
			COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/hostroam.sh
				$<TARGET_FILE:comrade-e2e>
				$<TARGET_FILE:comrade-dhtseed>)
		set_tests_properties(hostroam_e2e PROPERTIES
			SKIP_RETURN_CODE 77 TIMEOUT 200
			FIXTURES_REQUIRED swarm
			ENVIRONMENT COMRADE_SWARM_FILE=${COMRADE_SWARM_FILE})

		# Clients join on a token minted before the host had a
		# rendezvous node, and must be told of the one it qualified
		# afterwards. DHT rendezvous, so SKIPs without the net gate.
		add_test(NAME rdvsync_e2e
			COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/rdvsync.sh
				$<TARGET_FILE:comrade-e2e>
				$<TARGET_FILE:comrade-dhtseed>)
		set_tests_properties(rdvsync_e2e PROPERTIES
			SKIP_RETURN_CODE 77 TIMEOUT 240
			FIXTURES_REQUIRED swarm
			ENVIRONMENT COMRADE_SWARM_FILE=${COMRADE_SWARM_FILE})

		# Each of these stands up its own DHT node and multicast
		# announcer on this host, so under `ctest -j` they contend for
		# the segment and each other's rendezvous timing. Serialise them
		# however ctest is invoked.
		set_tests_properties(multiuser_e2e isolated_lan_e2e
			lan_concurrent_e2e lan_mixed_e2e turnstile_stuck_e2e
			roam_lan_e2e roam_fam_e2e roam_client_e2e
			path_switch_e2e resume_e2e
			hostroam_e2e rdvsync_e2e
			PROPERTIES RESOURCE_LOCK comrade_net)
	endif()
endif()

#
# The tests wrap load-bearing calls -- socketpair, pthread_create, bind,
# listen -- in assert(), and every distribution builds Release, which defines
# NDEBUG and would compile those calls clean away: the suite would then pass
# while doing nothing, or fail obscurely. Keep assertions live in the test
# binaries themselves; library code keeps the NDEBUG the build type asked for.
#
if(BUILD_TESTING)
	foreach(t IN ITEMS
		token_test tokgen_test netstate_test nsfacts_test
		hostreap_test sigquiet_test claimlog_test hbeat_test replay_test
		termfilter_test
		ctlproto_test netmon_test
		candpolicy_test candpack_test mailbox_test roauth_test
		connkey_test dataauth_test box_test
		stunprobe_test path_test bep44_test
		bep44_pin_test bep44_store_test bep44_rl_test
		sig_rebuild_test natstream_test stream_room_test
		stream_cc_test sshloop_test sshfwd_test sshexit_test sshro_test
		sshkcp_test sshctl_test qr_test showfmt_test mview_test)
		if(TARGET ${t})
			target_compile_options(${t} PRIVATE -UNDEBUG)
			# A test binary should run from where it was built, as
			# comrade.exe does: without this the toolchain's
			# winpthread and libgcc are looked for beside it and
			# the test dies before main with 0xc0000135.
			if(WIN32)
				target_link_options(${t} PRIVATE
					${COMRADE_WIN_LINK})
			endif()
		endif()
	endforeach()
endif()
