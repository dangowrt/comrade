cmake_minimum_required(VERSION 3.20)

project(comrade VERSION 0.0.1 LANGUAGES C)

include(GNUInstallDirs)
include(CTest)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Wextra)

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

add_library(comrade_token STATIC src/base64.c src/token.c)
target_include_directories(comrade_token PUBLIC src)

set(COMRADE_HAVE_CRYPTO 0)
if(MONOCYPHER_FOUND)
	set(COMRADE_HAVE_CRYPTO 1)
	add_library(comrade_crypto STATIC src/sha1.c src/bencode.c src/keys.c src/netmon.c)
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

add_library(comrade_sig STATIC src/sig_bep44.c)
target_include_directories(comrade_sig PUBLIC src)
if(COMRADE_HAVE_DHT)
	target_link_libraries(comrade_sig PUBLIC comrade_dht)
	target_compile_definitions(comrade_sig PRIVATE COMRADE_HAVE_DHT=1)
endif()

add_library(comrade_nat STATIC src/nat.c)
target_include_directories(comrade_nat PUBLIC src)
if(TARGET LibJuice::LibJuice)
	target_link_libraries(comrade_nat PUBLIC LibJuice::LibJuice)
endif()

add_library(comrade_stream STATIC src/stream.c)
target_include_directories(comrade_stream PUBLIC src)
if(TARGET kcp::kcp)
	target_link_libraries(comrade_stream PUBLIC kcp::kcp)
endif()

add_library(comrade_ssh STATIC src/sshd.c src/sshc.c)
target_include_directories(comrade_ssh PUBLIC src)
target_link_libraries(comrade_ssh PUBLIC comrade_token)
if(LIBSSH_FOUND)
	target_link_libraries(comrade_ssh PUBLIC PkgConfig::LIBSSH)
endif()

add_library(comrade_host STATIC src/host.c)
target_include_directories(comrade_host PUBLIC src)
target_link_libraries(comrade_host PUBLIC comrade_token)

add_executable(comrade src/main.c)
target_link_libraries(comrade
	comrade_host
	comrade_ssh
	comrade_sig
	comrade_nat
	comrade_stream
	comrade_token
)

install(TARGETS comrade RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

if(BUILD_TESTING)
	add_executable(token_test tests/token_test.c)
	target_link_libraries(token_test comrade_token)
	add_test(NAME token_test COMMAND token_test)

	# Both exercise the BEP 44 engine alone, which needs no DHT library.
	add_executable(bep44_test tests/bep44_test.c)
	target_link_libraries(bep44_test comrade_bep44)
	add_test(NAME bep44_test COMMAND bep44_test)

endif()

if(COMRADE_BUILD_TOOLS)
	add_executable(comrade-sigprobe tools/sigprobe.c)
	target_link_libraries(comrade-sigprobe comrade_dht comrade_token)

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
		token_test bep44_test)
		if(TARGET ${t})
			target_compile_options(${t} PRIVATE -UNDEBUG)
		endif()
	endforeach()
endif()
