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

set(COMRADE_HAVE_CRYPTO 0)
if(MONOCYPHER_FOUND)
	set(COMRADE_HAVE_CRYPTO 1)
	add_library(comrade_crypto STATIC src/sha1.c src/bencode.c src/keys.c src/netmon.c src/candpolicy.c)
	target_include_directories(comrade_crypto PUBLIC src)
	if(TARGET PkgConfig::MONOCYPHER)
		target_link_libraries(comrade_crypto PUBLIC PkgConfig::MONOCYPHER)
	else()
		target_include_directories(comrade_crypto PUBLIC ${MONOCYPHER_INCLUDE_DIR})
		target_link_libraries(comrade_crypto PUBLIC ${MONOCYPHER_LIBRARY})
	endif()
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
	target_link_libraries(comrade_dht PUBLIC comrade_crypto)
endif()

set(COMRADE_HAVE_SIG 0)
if(COMRADE_HAVE_DHT)
	set(COMRADE_HAVE_SIG 1)
	add_library(comrade_sig STATIC src/sig.c src/sig_mcast.c)
	target_include_directories(comrade_sig PUBLIC src)
	target_link_libraries(comrade_sig PUBLIC comrade_dht)
endif()

find_package(Threads REQUIRED)

set(COMRADE_HAVE_NAT 0)
add_library(comrade_nat STATIC src/nat.c)
target_include_directories(comrade_nat PUBLIC src)
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
	target_link_libraries(comrade_ssh PUBLIC comrade_token PkgConfig::LIBSSH Threads::Threads)
	find_library(COMRADE_UTIL util)
	if(COMRADE_UTIL)
		target_link_libraries(comrade_ssh PUBLIC ${COMRADE_UTIL})
	endif()
endif()

add_library(comrade_host STATIC src/host.c)
target_include_directories(comrade_host PUBLIC src)
target_link_libraries(comrade_host PUBLIC comrade_token)

add_executable(comrade src/main.c)
target_link_libraries(comrade
	comrade_host
	comrade_token
)
if(COMRADE_HAVE_SIG)
	target_link_libraries(comrade comrade_sig)
endif()

install(TARGETS comrade RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

if(BUILD_TESTING)
	add_executable(token_test tests/token_test.c)
	target_link_libraries(token_test comrade_token)
	add_test(NAME token_test COMMAND token_test)

	add_executable(tokgen_test tests/tokgen_test.c)
	target_link_libraries(tokgen_test comrade_token)
	add_test(NAME tokgen_test COMMAND tokgen_test)

	add_executable(netmon_test tests/netmon_test.c)
	target_link_libraries(netmon_test comrade_crypto)
	add_test(NAME netmon_test COMMAND netmon_test)

	add_executable(candpolicy_test tests/candpolicy_test.c)
	target_link_libraries(candpolicy_test comrade_crypto)
	add_test(NAME candpolicy_test COMMAND candpolicy_test)

	# Both exercise the BEP 44 engine alone, which needs no DHT library.
	add_executable(bep44_test tests/bep44_test.c)
	target_link_libraries(bep44_test comrade_bep44)
	add_test(NAME bep44_test COMMAND bep44_test)

	add_executable(natstream_test tests/natstream_test.c)
	target_link_libraries(natstream_test comrade_nat comrade_stream)
	add_test(NAME natstream_test COMMAND natstream_test)
	set_tests_properties(natstream_test PROPERTIES TIMEOUT 60)

	add_executable(sshloop_test tests/sshloop_test.c)
	target_link_libraries(sshloop_test comrade_ssh comrade_token Threads::Threads)
	add_test(NAME sshloop_test COMMAND sshloop_test)
	set_tests_properties(sshloop_test PROPERTIES TIMEOUT 30)

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
		token_test tokgen_test netmon_test candpolicy_test bep44_test
		natstream_test sshloop_test sshkcp_test)
		if(TARGET ${t})
			target_compile_options(${t} PRIVATE -UNDEBUG)
		endif()
	endforeach()
endif()
