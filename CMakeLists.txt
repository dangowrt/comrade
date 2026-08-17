cmake_minimum_required(VERSION 3.20)

project(comrade VERSION 0.0.1 LANGUAGES C)

include(GNUInstallDirs)
include(CTest)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Wextra)

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
pkg_check_modules(MONOCYPHER IMPORTED_TARGET monocypher)
if(NOT MONOCYPHER_FOUND)
	find_path(MONOCYPHER_INCLUDE_DIR monocypher.h)
	find_library(MONOCYPHER_LIBRARY monocypher)
	if(MONOCYPHER_INCLUDE_DIR AND MONOCYPHER_LIBRARY)
		set(MONOCYPHER_FOUND 1)
	endif()
endif()

set(COMRADE_DHT_DIR "" CACHE PATH "Directory containing dht.c and dht.h from jech/dht")

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
if(NOT MONOCYPHER_FOUND)
	list(APPEND COMRADE_MISSING "monocypher (pkg-config module or monocypher.h + libmonocypher)")
endif()
if(NOT (COMRADE_DHT_DIR AND EXISTS "${COMRADE_DHT_DIR}/dht.c"))
	list(APPEND COMRADE_MISSING "dht (jech/dht checkout, set COMRADE_DHT_DIR)")
endif()
if(COMRADE_MISSING)
	list(JOIN COMRADE_MISSING "\n   " COMRADE_MISSING_TEXT)
	message(STATUS "Missing dependencies, tolerated while the modules using them are stubs:\n   ${COMRADE_MISSING_TEXT}")
endif()

add_library(comrade_token STATIC src/base64.c src/base58.c src/token.c src/tokgen.c)
target_include_directories(comrade_token PUBLIC src)

# Per-user application data directory (STUN list, cached DHT nodes).
add_library(comrade_appdir STATIC src/appdir.c)
target_include_directories(comrade_appdir PUBLIC src)

# Structured connection status (controller fills it, view renders it) and the
# view that paints it on the reserved bottom terminal row.
add_library(comrade_dbg STATIC src/dbg.c)
target_include_directories(comrade_dbg PUBLIC src)

add_library(comrade_termfilter STATIC src/termfilter.c)
target_include_directories(comrade_termfilter PUBLIC src)

add_library(comrade_ctlproto STATIC src/ctlproto.c)
target_include_directories(comrade_ctlproto PUBLIC src)

add_library(comrade_conn STATIC src/conn.c)
target_include_directories(comrade_conn PUBLIC src)

add_library(comrade_statusbar STATIC src/statusbar.c)
target_include_directories(comrade_statusbar PUBLIC src)
target_link_libraries(comrade_statusbar PUBLIC comrade_conn)

# STUN server pool. The default set is baked in at configure time from the
# always-online-stun submodule (its RFC 5780-capable list, which also serves
# for plain reflexive gathering); `comrade stun-update` refreshes it into the
# user's data folder at runtime. The list is never copied into our own tree.
set(STUN_LIST_SRC "${CMAKE_CURRENT_SOURCE_DIR}/deps/always-online-stun/valid_nat_testing_hosts.txt")
set(STUN_BUNDLE_INC "${CMAKE_CURRENT_BINARY_DIR}/stun_bundle.inc")
if(EXISTS "${STUN_LIST_SRC}")
	file(STRINGS "${STUN_LIST_SRC}" STUN_LIST_LINES)
else()
	message(WARNING "always-online-stun submodule not present; baking a minimal STUN fallback. Run: git submodule update --init --depth 1 deps/always-online-stun")
	set(STUN_LIST_LINES "stun.nextcloud.com:443" "stun.sipgate.net:3478" "stun.ipfire.org:3478")
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

set(COMRADE_HAVE_CRYPTO 0)
if(MONOCYPHER_FOUND)
	set(COMRADE_HAVE_CRYPTO 1)
	add_library(comrade_crypto STATIC src/sha1.c src/bencode.c src/keys.c src/netmon.c src/candpolicy.c src/candpack.c)
	target_include_directories(comrade_crypto PUBLIC src)
	if(TARGET PkgConfig::MONOCYPHER)
		target_link_libraries(comrade_crypto PUBLIC PkgConfig::MONOCYPHER)
	else()
		target_include_directories(comrade_crypto PUBLIC ${MONOCYPHER_INCLUDE_DIR})
		target_link_libraries(comrade_crypto PUBLIC ${MONOCYPHER_LIBRARY})
	endif()
endif()

# The rendezvous mailbox: the two-slot container plus turnstile claim logic
# (bencode only, no crypto or DHT), extracted from sig.c so it is unit-testable.
if(COMRADE_HAVE_CRYPTO)
	add_library(comrade_mailbox STATIC src/mailbox.c)
	target_include_directories(comrade_mailbox PUBLIC src)
	target_link_libraries(comrade_mailbox PUBLIC comrade_crypto)
endif()

set(COMRADE_HAVE_DHT 0)
if(COMRADE_HAVE_CRYPTO AND COMRADE_DHT_DIR AND EXISTS "${COMRADE_DHT_DIR}/dht.c")
	set(COMRADE_HAVE_DHT 1)
	add_library(comrade_dht STATIC
		${COMRADE_DHT_DIR}/dht.c
		src/bep44.c
		src/dhtnode.c
	)
	target_include_directories(comrade_dht PUBLIC src ${COMRADE_DHT_DIR})
	target_compile_definitions(comrade_dht PRIVATE _GNU_SOURCE)
	set_source_files_properties(${COMRADE_DHT_DIR}/dht.c PROPERTIES
		COMPILE_OPTIONS "-w")
	target_link_libraries(comrade_dht PUBLIC comrade_crypto comrade_appdir Threads::Threads)
endif()

set(COMRADE_HAVE_SIG 0)
if(COMRADE_HAVE_DHT)
	set(COMRADE_HAVE_SIG 1)
	add_library(comrade_sig STATIC src/sig.c src/sig_mcast.c)
	target_include_directories(comrade_sig PUBLIC src)
	target_link_libraries(comrade_sig PUBLIC comrade_dht comrade_mailbox)
endif()

find_package(Threads REQUIRED)

set(COMRADE_HAVE_NAT 0)
add_library(comrade_nat STATIC src/nat.c)
target_include_directories(comrade_nat PUBLIC src)

add_library(comrade_lanlink STATIC src/lanlink.c)
target_include_directories(comrade_lanlink PUBLIC src)
if(TARGET LibJuice::LibJuice)
	target_link_libraries(comrade_nat PUBLIC LibJuice::LibJuice)
	set(COMRADE_HAVE_NAT 1)
endif()

set(COMRADE_HAVE_STREAM 0)
add_library(comrade_stream STATIC src/stream.c)
target_include_directories(comrade_stream PUBLIC src)
target_link_libraries(comrade_stream PUBLIC Threads::Threads)
if(TARGET kcp::kcp)
	target_link_libraries(comrade_stream PUBLIC kcp::kcp)
	set(COMRADE_HAVE_STREAM 1)
endif()

if(COMRADE_HAVE_STREAM)
	add_library(comrade_bridge STATIC src/sshbridge.c)
	target_include_directories(comrade_bridge PUBLIC src)
	target_link_libraries(comrade_bridge PUBLIC comrade_stream)
endif()

set(COMRADE_HAVE_SSH 0)
if(LIBSSH_FOUND)
	set(COMRADE_HAVE_SSH 1)
	add_library(comrade_ssh STATIC src/sshd.c src/sshc.c)
	target_include_directories(comrade_ssh PUBLIC src)
	# The message-based libssh server API is deprecated in favour of the
	# callback API but is clearer and fully functional; migrate later.
	target_compile_options(comrade_ssh PRIVATE -Wno-deprecated-declarations)
	target_link_libraries(comrade_ssh PUBLIC comrade_token comrade_statusbar comrade_dbg comrade_termfilter PkgConfig::LIBSSH Threads::Threads)
	find_library(COMRADE_UTIL util)
	if(COMRADE_UTIL)
		target_link_libraries(comrade_ssh PUBLIC ${COMRADE_UTIL})
	endif()
endif()

set(COMRADE_HAVE_SESSION 0)
if(COMRADE_HAVE_SIG AND COMRADE_HAVE_NAT AND COMRADE_HAVE_STREAM AND COMRADE_HAVE_SSH)
	set(COMRADE_HAVE_SESSION 1)
	add_library(comrade_session STATIC src/session.c)
	target_include_directories(comrade_session PUBLIC src)
	target_link_libraries(comrade_session PUBLIC
		comrade_sig comrade_nat comrade_lanlink comrade_stream comrade_ssh
		comrade_bridge comrade_token comrade_crypto comrade_stunlist comrade_conn
		comrade_ctlproto comrade_dbg)

	# The view: the only module that draws to the terminal (MVC).
	add_library(comrade_ui STATIC src/ui.c)
	target_include_directories(comrade_ui PUBLIC src)
	target_link_libraries(comrade_ui PUBLIC comrade_token)
endif()

add_library(comrade_host STATIC src/host.c)
target_include_directories(comrade_host PUBLIC src)
target_link_libraries(comrade_host PUBLIC comrade_token comrade_dbg comrade_termfilter)
if(COMRADE_HAVE_SESSION)
	target_link_libraries(comrade_host PUBLIC comrade_session comrade_ui)
	target_compile_definitions(comrade_host PRIVATE COMRADE_HAVE_SESSION=1)
endif()

add_executable(comrade src/main.c)
target_link_libraries(comrade
	comrade_host
	comrade_token
	comrade_stunlist
	comrade_statusbar
)
if(COMRADE_HAVE_SESSION)
	target_link_libraries(comrade comrade_session comrade_ui)
	target_compile_definitions(comrade PRIVATE COMRADE_HAVE_SESSION=1)
endif()

install(TARGETS comrade RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

if(BUILD_TESTING)
	add_executable(token_test tests/token_test.c)
	target_link_libraries(token_test comrade_token)
	add_test(NAME token_test COMMAND token_test)

	add_executable(tokgen_test tests/tokgen_test.c)
	target_link_libraries(tokgen_test comrade_token)
	add_test(NAME tokgen_test COMMAND tokgen_test)

	add_executable(termfilter_test tests/termfilter_test.c)
	target_link_libraries(termfilter_test comrade_termfilter)
	add_test(NAME termfilter_test COMMAND termfilter_test)

	add_executable(ctlproto_test tests/ctlproto_test.c)
	target_link_libraries(ctlproto_test comrade_ctlproto)
	add_test(NAME ctlproto_test COMMAND ctlproto_test)

	add_executable(netmon_test tests/netmon_test.c)
	target_link_libraries(netmon_test comrade_crypto)
	add_test(NAME netmon_test COMMAND netmon_test)

	add_executable(candpolicy_test tests/candpolicy_test.c)
	target_link_libraries(candpolicy_test comrade_crypto)
	add_test(NAME candpolicy_test COMMAND candpolicy_test)

	add_executable(candpack_test tests/candpack_test.c)
	target_link_libraries(candpack_test comrade_crypto)
	add_test(NAME candpack_test COMMAND candpack_test)

	add_executable(mailbox_test tests/mailbox_test.c)
	target_link_libraries(mailbox_test comrade_mailbox)
	add_test(NAME mailbox_test COMMAND mailbox_test)

	# Both exercise the BEP 44 engine alone, which needs no DHT library.
	add_executable(bep44_test tests/bep44_test.c)
	target_link_libraries(bep44_test comrade_bep44)
	add_test(NAME bep44_test COMMAND bep44_test)

	add_executable(bep44_pin_test tests/bep44_pin_test.c)
	target_link_libraries(bep44_pin_test comrade_bep44)
	add_test(NAME bep44_pin_test COMMAND bep44_pin_test)
	set_tests_properties(bep44_pin_test PROPERTIES TIMEOUT 15)

	add_executable(natstream_test tests/natstream_test.c)
	target_link_libraries(natstream_test comrade_nat comrade_stream)
	add_test(NAME natstream_test COMMAND natstream_test)
	set_tests_properties(natstream_test PROPERTIES TIMEOUT 60)

	add_executable(sshloop_test tests/sshloop_test.c)
	target_link_libraries(sshloop_test comrade_ssh comrade_token Threads::Threads)
	add_test(NAME sshloop_test COMMAND sshloop_test)
	set_tests_properties(sshloop_test PROPERTIES TIMEOUT 30)

	add_executable(sshexit_test tests/sshexit_test.c)
	target_link_libraries(sshexit_test comrade_ssh comrade_token Threads::Threads)
	add_test(NAME sshexit_test COMMAND sshexit_test)
	set_tests_properties(sshexit_test PROPERTIES TIMEOUT 30)

	add_executable(sshkcp_test tests/sshkcp_test.c)
	target_link_libraries(sshkcp_test
		comrade_ssh comrade_bridge comrade_stream comrade_token Threads::Threads)
	add_test(NAME sshkcp_test COMMAND sshkcp_test)
	add_executable(sshctl_test tests/sshctl_test.c)
	target_link_libraries(sshctl_test comrade_ssh comrade_bridge comrade_stream comrade_token Threads::Threads)
	add_test(NAME sshctl_test COMMAND sshctl_test)
	set_tests_properties(sshkcp_test PROPERTIES TIMEOUT 30)
endif()

if(COMRADE_BUILD_TOOLS)
	add_executable(comrade-sigprobe tools/sigprobe.c)
	target_link_libraries(comrade-sigprobe comrade_dht comrade_token)

	add_executable(comrade-rdvbench tools/rdvbench.c)
	target_link_libraries(comrade-rdvbench comrade_dht comrade_token)

	add_executable(comrade-e2e tools/e2e.c)
	target_link_libraries(comrade-e2e comrade_session)
	if(COMRADE_STATIC)
		target_link_options(comrade-e2e PRIVATE -static)
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
		token_test tokgen_test termfilter_test ctlproto_test netmon_test
		candpolicy_test candpack_test mailbox_test bep44_test
		bep44_pin_test natstream_test sshloop_test sshexit_test
		sshkcp_test sshctl_test)
		if(TARGET ${t})
			target_compile_options(${t} PRIVATE -UNDEBUG)
		endif()
	endforeach()
endif()
