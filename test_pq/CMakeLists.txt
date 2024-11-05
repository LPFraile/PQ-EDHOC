# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.13.1)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(auto_test)

if(COMMAND_LINE_FLAGS MATCHES "ASAN")
target_compile_options(app PRIVATE -fsanitize=address -fomit-frame-pointer)
endif()

option(USE_SUIT_2 "Enable SUIT 2" OFF)
option(USE_SUIT_7 "Enable SUIT 7" OFF)
option(USE_SUIT_9 "Enable SUIT 9" OFF)
option(USE_SUIT_12 "Enable SUIT 12" OFF)
option(USE_SUIT_11 "Enable SUIT 11" OFF)
option(USE_SUIT_13 "Enable SUIT 13" OFF)

if(USE_SUIT_2)
  message(STATUS "SUIT 2 enable")
  FILE(GLOB app_sources
    *.c
    edhoc_integration_tests/*.c
    ../externals/zcbor/src/*.c
    ../externals/compact25519/src/c25519/*.c
    ../externals/compact25519/src/*.c
    #../externals/mbedtls/library/*.c
    ../externals/tinycrypt/lib/source/*.c
    /sha256.c
    ../test_vectors/*.c
    )
  
  target_include_directories(app PRIVATE $ENV{ZEPHYR_BASE}/include)
  target_include_directories(app PRIVATE 
    $ENV{ZEPHYR_BASE}/subsys/net/ip
    .
    #../../common
    ../inc
    ../test_vectors
    ../externals/zcbor/include 
  #  ../externals/mbedtls/library 
  #  ../externals/mbedtls/include 
  #  ../externals/mbedtls/include/mbedtls 
  #  ../externals/mbedtls/include/psa
    ../externals/tinycrypt/lib/include)
  target_compile_definitions(app PRIVATE USE_SUIT_2)
endif()

if(USE_SUIT_7)
  FILE(GLOB app_sources
  *.c
  edhoc_integration_tests/*.c
  ../externals/zcbor/src/*.c
  ../externals/compact25519/src/c25519/*.c
  ../externals/compact25519/src/*.c
 # ../externals/mbedtls/library/*.c
  ../externals/tinycrypt/lib/source/*.c
  ../test_vectors/*.c
  ../externals/pqm4/crypto_kem/kyber512/m4fstack/*.c
  ../externals/pqm4/crypto_kem/kyber512/m4fstack/*.i
  ../externals/pqm4/crypto_kem/kyber512/m4fstack/*.S
  ../externals/pqm4/crypto_sign/falcon-512/m4-ct/*.c
  ../externals/pqm4/crypto_sign/falcon-512/m4-ct/*.i
  ../externals/pqm4/crypto_sign/falcon-512/m4-ct/*.S
  ../externals/pqm4/crypto_sign/falcon-512/m4-ct/*.s
  ../externals/pqm4/common/randombytes.c
  ../externals/pqm4/common/keccakf1600.S
  ../externals/pqm4/common/crypto_hashblocks_sha512*.*
  ../externals/pqm4/common/aes.*
  ../externals/pqm4/mupq/common/fips202.c
  )

  target_include_directories(app PRIVATE $ENV{ZEPHYR_BASE}/include)
  target_include_directories(app PRIVATE 
    $ENV{ZEPHYR_BASE}/subsys/net/ip
    .
    #../../common
    ../inc
    ../test_vectors
    ../externals/zcbor/include 
   # ../externals/mbedtls/library 
   # ../externals/mbedtls/include 
   # ../externals/mbedtls/include/mbedtls 
   # ../externals/mbedtls/include/psa
    ../externals/tinycrypt/lib/include
    ../externals/pqm4/crypto_kem/kyber512/m4fstack
    ../externals/pqm4/crypto_sign/falcon-512/m4-ct
    ../externals/pqm4/mupq/common
    ../externals/pqm4/libopencm3/include)
  target_compile_definitions(app PRIVATE USE_SUIT_7)
endif()

if(USE_SUIT_9)
  FILE(GLOB app_sources
  *.c
  edhoc_integration_tests/*.c
  ../externals/zcbor/src/*.c
  ../externals/compact25519/src/c25519/*.c
  ../externals/compact25519/src/*.c
  #../externals/mbedtls/library/*.c
  ../externals/tinycrypt/lib/source/*.c
  ../test_vectors/*.c
  ../externals/pqm4/crypto_kem/kyber768/m4fstack/*.c
  ../externals/pqm4/crypto_kem/kyber768/m4fstack/*.i
  ../externals/pqm4/crypto_kem/kyber768/m4fstack/*.S
  ../externals/pqm4/crypto_sign/falcon-512/m4-ct/*.c
  ../externals/pqm4/crypto_sign/falcon-512/m4-ct/*.i
  ../externals/pqm4/crypto_sign/falcon-512/m4-ct/*.S
  ../externals/pqm4/crypto_sign/falcon-512/m4-ct/*.s
  ../externals/pqm4/common/randombytes.c
  ../externals/pqm4/common/keccakf1600.S
  ../externals/pqm4/common/crypto_hashblocks_sha512*.*
  ../externals/pqm4/common/aes.*
  ../externals/pqm4/mupq/common/fips202.c
  )

  target_include_directories(app PRIVATE $ENV{ZEPHYR_BASE}/include)
  target_include_directories(app PRIVATE 
    $ENV{ZEPHYR_BASE}/subsys/net/ip
    .
    #../../common
    ../inc
    ../test_vectors
    ../externals/zcbor/include 
    #../externals/mbedtls/library 
    #../externals/mbedtls/include 
    #../externals/mbedtls/include/mbedtls 
    #../externals/mbedtls/include/psa
    ../externals/tinycrypt/lib/include
    ../externals/pqm4/crypto_kem/kyber768/m4fstack
    ../externals/pqm4/crypto_sign/falcon-512/m4-ct
    ../externals/pqm4/mupq/common
    ../externals/pqm4/libopencm3/include)
  target_compile_definitions(app PRIVATE USE_SUIT_9)
endif()

if(USE_SUIT_10)
  FILE(GLOB app_sources
  *.c
  edhoc_integration_tests/*.c
  ../externals/zcbor/src/*.c
  ../externals/compact25519/src/c25519/*.c
  ../externals/compact25519/src/*.c
  #../externals/mbedtls/library/*.c
  ../externals/tinycrypt/lib/source/*.c
  ../test_vectors/*.c
  ../externals/PQClean/crypto_kem/hqc-128/clean/*.c
  ../externals/pqm4/crypto_sign/falcon-512/m4-ct/*.c
  ../externals/pqm4/crypto_sign/falcon-512/m4-ct/*.i
  ../externals/pqm4/crypto_sign/falcon-512/m4-ct/*.S
  ../externals/pqm4/crypto_sign/falcon-512/m4-ct/*.s
  ../externals/pqm4/common/randombytes.c
  ../externals/pqm4/common/keccakf1600.S
  ../externals/pqm4/common/crypto_hashblocks_sha512*.*
  ../externals/pqm4/common/aes.*
  ../externals/pqm4/mupq/common/fips202.c
  )

  target_include_directories(app PRIVATE $ENV{ZEPHYR_BASE}/include)
  target_include_directories(app PRIVATE 
    $ENV{ZEPHYR_BASE}/subsys/net/ip
    .
    #../../common
    ../inc
    ../test_vectors
    ../externals/zcbor/include 
    #../externals/mbedtls/library 
    #../externals/mbedtls/include 
    #../externals/mbedtls/include/mbedtls 
    #../externals/mbedtls/include/psa
    ../externals/tinycrypt/lib/include
    ../externals/PQClean/crypto_kem/hqc-128/clean
    ../externals/pqm4/crypto_sign/falcon-512/m4-ct
    ../externals/pqm4/mupq/common
    ../externals/pqm4/libopencm3/include)
  target_compile_definitions(app PRIVATE USE_SUIT_10)
endif()



if(USE_SUIT_11)
  FILE(GLOB app_sources
  *.c
  edhoc_integration_tests/*.c
  ../externals/zcbor/src/*.c
  ../externals/compact25519/src/c25519/*.c
  ../externals/compact25519/src/*.c
  #../externals/mbedtls/library/*.c
  ../externals/tinycrypt/lib/source/*.c
  ../test_vectors/*.c
  ../externals/pqm4/crypto_kem/bikel1/m4f/*.c
	../externals/pqm4/crypto_kem/bikel1/m4f/*.i
	../externals/pqm4/crypto_kem/bikel1/m4f/*.S
	../externals/pqm4/crypto_kem/bikel1/m4f/*.s
  ../externals/pqm4/crypto_sign/falcon-512/m4-ct/*.c
  ../externals/pqm4/crypto_sign/falcon-512/m4-ct/*.i
  ../externals/pqm4/crypto_sign/falcon-512/m4-ct/*.S
  ../externals/pqm4/crypto_sign/falcon-512/m4-ct/*.s
  ../externals/pqm4/common/randombytes.c
  ../externals/pqm4/common/keccakf1600.S
  ../externals/pqm4/common/crypto_hashblocks_sha512*.*
  ../externals/pqm4/common/*.S
  ../externals/pqm4/common/aes.*
  ../externals/pqm4/mupq/common/fips202.c
  ../externals/pqm4/mupq/common/sha2.c
  )

  target_include_directories(app PRIVATE $ENV{ZEPHYR_BASE}/include)
  target_include_directories(app PRIVATE 
    $ENV{ZEPHYR_BASE}/subsys/net/ip
    .
    #../../common
    ../inc
    ../test_vectors
    ../externals/zcbor/include 
    #../externals/mbedtls/library 
    #../externals/mbedtls/include 
    #../externals/mbedtls/include/mbedtls 
    #../externals/mbedtls/include/psa
    ../externals/tinycrypt/lib/include
    ../externals/pqm4/crypto_kem/bikel1/m4f
    ../externals/pqm4/crypto_sign/falcon-512/m4-ct
   # ../externals/pqm4/common
    ../externals/pqm4/mupq/common
    #../externals/pqm4/mupq/pqclean/common
    ../externals/pqm4/libopencm3/include)
  target_compile_definitions(app PRIVATE USE_SUIT_11)
endif()


if(USE_SUIT_12)
  FILE(GLOB app_sources
  *.c
  edhoc_integration_tests/*.c
  ../externals/zcbor/src/*.c
  ../externals/compact25519/src/c25519/*.c
  ../externals/compact25519/src/*.c
  #../externals/mbedtls/library/*.c
  ../externals/tinycrypt/lib/source/*.c
  ../test_vectors/*.c
  ../externals/pqm4/crypto_kem/kyber512/m4fstack/*.c
  ../externals/pqm4/crypto_kem/kyber512/m4fstack/*.i
  ../externals/pqm4/crypto_kem/kyber512/m4fstack/*.S
	#../externals/pqm4/crypto_sign/dilithium2/m4f/*.c
	#../externals/pqm4/crypto_sign/dilithium2/m4f/*.i
	#../externals/pqm4/crypto_sign/dilithium2/m4f/*.S
	#../externals/pqm4/crypto_sign/dilithium2/m4f/*.s
  
  ../externals/pqm4/crypto_sign/dilithium2/m4fstack/*.c
	../externals/pqm4/crypto_sign/dilithium2/m4fstack/*.i
	../externals/pqm4/crypto_sign/dilithium2/m4fstack/*.S
	../externals/pqm4/crypto_sign/dilithium2/m4fstack/*.s
  
  ../externals/pqm4/common/randombytes.c

  ../externals/pqm4/common/keccakf1600.S
  #../externals/pqm4/mupq/common/keccakf1600.c
  ../externals/pqm4/common/crypto_hashblocks_sha512*.*
  ../externals/pqm4/common/aes.*
  ../externals/pqm4/mupq/common/fips202.c
  )

  target_include_directories(app PRIVATE $ENV{ZEPHYR_BASE}/include)
  target_include_directories(app PRIVATE 
    $ENV{ZEPHYR_BASE}/subsys/net/ip
    .
    #../../common
    ../inc
    ../test_vectors
    ../externals/zcbor/include 
   # ../externals/mbedtls/library 
   # ../externals/mbedtls/include 
   # ../externals/mbedtls/include/mbedtls 
   # ../externals/mbedtls/include/psa
    ../externals/tinycrypt/lib/include
    ../externals/pqm4/crypto_kem/kyber512/m4fstack
    #../externals/pqm4/crypto_sign/dilithium2/m4f
    ../externals/pqm4/crypto_sign/dilithium2/m4fstack
    
    ../externals/pqm4/mupq/common
    ../externals/pqm4/libopencm3/include)
  target_compile_definitions(app PRIVATE USE_SUIT_12)
endif()



if(USE_SUIT_13)
  FILE(GLOB app_sources
  *.c
  edhoc_integration_tests/*.c
  ../externals/zcbor/src/*.c
  ../externals/compact25519/src/c25519/*.c
  ../externals/compact25519/src/*.c
  #../externals/mbedtls/library/*.c
  ../externals/tinycrypt/lib/source/*.c
  ../test_vectors/*.c
  ../externals/pqm4/crypto_kem/bikel1/m4f/*.c
	../externals/pqm4/crypto_kem/bikel1/m4f/*.i
	../externals/pqm4/crypto_kem/bikel1/m4f/*.S
	../externals/pqm4/crypto_kem/bikel1/m4f/*.s
	../externals/pqm4/crypto_sign/dilithium2/m4fstack/*.c
	../externals/pqm4/crypto_sign/dilithium2/m4fstack/*.i
	../externals/pqm4/crypto_sign/dilithium2/m4fstack/*.S
	../externals/pqm4/crypto_sign/dilithium2/m4fstack/*.s
  ../externals/pqm4/common/randombytes.c
  ../externals/pqm4/common/keccakf1600.S
  ../externals/pqm4/common/crypto_hashblocks_sha512*.*
  ../externals/pqm4/common/*.S
  ../externals/pqm4/common/aes.*
  ../externals/pqm4/mupq/common/fips202.c
  ../externals/pqm4/mupq/common/sha2.c
  )

  target_include_directories(app PRIVATE $ENV{ZEPHYR_BASE}/include)
  target_include_directories(app PRIVATE 
    $ENV{ZEPHYR_BASE}/subsys/net/ip
    .
    #../../common
    ../inc
    ../test_vectors
    ../externals/zcbor/include 
    #../externals/mbedtls/library 
    #../externals/mbedtls/include 
    #../externals/mbedtls/include/mbedtls 
    #../externals/mbedtls/include/psa
    ../externals/tinycrypt/lib/include
    ../externals/pqm4/crypto_kem/bikel1/m4f
    ../externals/pqm4/crypto_sign/dilithium2/m4fstack
    ../externals/pqm4/mupq/common
    ../externals/pqm4/libopencm3/include)
  target_compile_definitions(app PRIVATE USE_SUIT_13)
endif()

if(USE_SUIT_14)
  FILE(GLOB app_sources
  *.c
  edhoc_integration_tests/*.c
  ../externals/zcbor/src/*.c
  ../externals/compact25519/src/c25519/*.c
  ../externals/compact25519/src/*.c
  #../externals/mbedtls/library/*.c
  ../externals/tinycrypt/lib/source/*.c
  ../test_vectors/*.c
  ../externals/pqm4/crypto_kem/kyber512/m4fstack/*.c
  ../externals/pqm4/crypto_kem/kyber512/m4fstack/*.i
  ../externals/pqm4/crypto_kem/kyber512/m4fstack/*.S
  ../externals/pqm4/mupq/crypto_sign/hawk512/ref/*.c
  ../externals/pqm4/common/randombytes.c
  ../externals/pqm4/common/keccakf1600.S
  ../externals/pqm4/common/crypto_hashblocks_sha512*.*
  ../externals/pqm4/common/aes.*
  ../externals/pqm4/mupq/common/fips202.c
  )

  target_include_directories(app PRIVATE $ENV{ZEPHYR_BASE}/include)
  target_include_directories(app PRIVATE 
    $ENV{ZEPHYR_BASE}/subsys/net/ip
    .
    #../../common
    ../inc
    ../test_vectors
    ../externals/zcbor/include 
    #../externals/mbedtls/library 
    #../externals/mbedtls/include 
    #../externals/mbedtls/include/mbedtls 
    #../externals/mbedtls/include/psa
    ../externals/tinycrypt/lib/include
    ../externals/pqm4/crypto_kem/kyber512/m4fstack
    ../externals/pqm4/mupq/crypto_sign/hawk512/ref
    ../externals/pqm4/mupq/common
    ../externals/pqm4/libopencm3/include)
  target_compile_definitions(app PRIVATE USE_SUIT_14)
endif()
if(USE_SUIT_15)
  FILE(GLOB app_sources
  *.c
  edhoc_integration_tests/*.c
  ../externals/zcbor/src/*.c
  ../externals/compact25519/src/c25519/*.c
  ../externals/compact25519/src/*.c
  #../externals/mbedtls/library/*.c
  ../externals/tinycrypt/lib/source/*.c
  ../test_vectors/*.c
  ../externals/pqm4/crypto_kem/kyber512/m4fstack/*.c
  ../externals/pqm4/crypto_kem/kyber512/m4fstack/*.i
  ../externals/pqm4/crypto_kem/kyber512/m4fstack/*.S
  ../externals/pqm4/crypto_sign/haetae2/m4f/*.c
  ../externals/pqm4/crypto_sign/haetae2/m4f/*.S
  ../externals/pqm4/crypto_sign/haetae2/m4f/*.i
  ../externals/pqm4/common/randombytes.c
  ../externals/pqm4/common/keccakf1600.S
  ../externals/pqm4/common/crypto_hashblocks_sha512*.*
  ../externals/pqm4/common/aes.*
  ../externals/pqm4/mupq/common/fips202.c
  )

  target_include_directories(app PRIVATE $ENV{ZEPHYR_BASE}/include)
  target_include_directories(app PRIVATE 
    $ENV{ZEPHYR_BASE}/subsys/net/ip
    .
    #../../common
    ../inc
    ../test_vectors
    ../externals/zcbor/include 
   # ../externals/mbedtls/library 
   # ../externals/mbedtls/include 
   # ../externals/mbedtls/include/mbedtls 
   # ../externals/mbedtls/include/psa
    ../externals/tinycrypt/lib/include
    ../externals/pqm4/crypto_kem/kyber512/m4fstack
    ../externals/pqm4/crypto_sign/haetae2/m4f
    ../externals/pqm4/mupq/common
    ../externals/pqm4/libopencm3/include)
  target_compile_definitions(app PRIVATE USE_SUIT_15)
endif()



if(USE_SUIT_16)
  FILE(GLOB app_sources
  *.c
  edhoc_integration_tests/*.c
  ../externals/zcbor/src/*.c
  ../externals/compact25519/src/c25519/*.c
  ../externals/compact25519/src/*.c
  #../externals/mbedtls/library/*.c
  ../externals/tinycrypt/lib/source/*.c
  ../test_vectors/*.c
  #../externals/pqm4/crypto_kem/kyber512/m4fstack/*.c
  #../externals/pqm4/crypto_kem/kyber512/m4fstack/*.i
  #../externals/pqm4/crypto_kem/kyber512/m4fstack/*.S
  ../externals/pqm4/crypto_sign/ov-Ip/m4f/*.c
  ../externals/pqm4/crypto_sign/ov-Ip/m4f/*.i
  ../externals/pqm4/crypto_sign/ov-Ip/m4f/*.S
  ../externals/pqm4/common/randombytes.c
  ../externals/pqm4/common/keccakf1600.S
  ../externals/pqm4/common/crypto_hashblocks_sha512*.*
  ../externals/pqm4/common/aes.*
  ../externals/pqm4/mupq/common/fips202.c
  )

  target_include_directories(app PRIVATE $ENV{ZEPHYR_BASE}/include)
  target_include_directories(app PRIVATE 
    $ENV{ZEPHYR_BASE}/subsys/net/ip
    .
    #../../common
    ../inc
    ../test_vectors
    ../externals/zcbor/include 
   # ../externals/mbedtls/library 
   # ../externals/mbedtls/include 
   # ../externals/mbedtls/include/mbedtls 
   # ../externals/mbedtls/include/psa
    ../externals/tinycrypt/lib/include
    #../externals/pqm4/crypto_kem/kyber512/m4fstack
    ../externals/pqm4/crypto_sign/ov-Ip/m4f
    ../externals/pqm4/mupq/common
    ../externals/pqm4/libopencm3/include)
  target_compile_definitions(app PRIVATE USE_SUIT_16)
endif()



target_sources(app PRIVATE ${app_sources})




add_definitions(
  #-DMBEDTLS_CONFIG_FILE="mbedtls_config_uoscore_uedhoc.h"
  -DUNIT_TEST
  #-DDEBUG_PRINT
  -DZCBOR_CANONICAL
  #-DMEASURE_LATENCY_ON
  #-DREPORT_STACK_USAGE
  #-DPOWER_MEASUREMENTS
  #-DMEASURE_LATENCY_PER_THREAD
  #-DMEASURE_CLK
)

if(DEFINED REPORT_STACK_USAGE)
add_definitions(-DREPORT_STACK_USAGE=${REPORT_STACK_USAGE})
endif()

if(DEFINED POWER_MEASUREMENTS)
add_definitions(-DPOWER_MEASUREMENTS=${POWER_MEASUREMENTS})
endif()

if(DEFINED MEASURE_LATENCY_PER_THREAD)
add_definitions(-DMEASURE_LATENCY_PER_THREAD=${MEASURE_LATENCY_PER_THREAD})
endif()

if(DEFINED MEASURE_CLK)
add_definitions(-DMEASURE_CLK=${MEASURE_CLK})
endif()

if(DEFINED AUTH_KEY_GEN)
add_definitions(-DAUTH_KEY_GEN=${AUTH_KEY_GEN})
endif()

if(DEFINED USE_X5CHAIN)
  add_definitions(-DUSE_X5CHAIN=${USE_X5CHAIN})
  message(STATUS "USE_X5CHAIN is defined")
elseif(DEFINED USE_X5T)
  add_definitions(-DUSE_X5T=${USE_X5T})
  message(STATUS "USE_X5T is defined")
endif()

if(DEFINED USE_TEST_SIG)
  add_definitions(-DUSE_TEST_SIG=${USE_TEST_SIG})
  message(STATUS "USE_TEST_SIG is defined")
endif()

if(DEFINED USE_TEST_KEM)
  add_definitions(-DUSE_TEST_KEM=${USE_TEST_KEM})
  message(STATUS "USE_TEST_KEM is defined")
endif()

if(DEFINED USE_TEST_EDHOC)
  add_definitions(-DUSE_TEST_EDHOC=${USE_TEST_EDHOC})
  message(STATUS "USE_TEST_EDHOC is defined")
endif()

if(DEFINED USE_TEST_INITIATOR)
  add_definitions(-DUSE_TEST_INITIATOR=${USE_TEST_INITIATOR})
  message(STATUS "USE_TEST_INITIATOR is defined")
endif()
if(DEFINED USE_TEST_RESPONDER)
  add_definitions(-DUSE_TEST_RESPONDER=${USE_TEST_RESPONDER})
  message(STATUS "USE_TEST_RESPONDER is defined")
endif()

if(DEFINED USE_INTE_NUM)
  add_definitions(-DUSE_INTE_NUM=${USE_INTE_NUM})
  message(STATUS "USE_TEST_EDHOC is defined")
endif()

set(CMAKE_ASM_FLAGS_RELEASE "" CACHE INTERNAL "ASM Compiler options for release build type")

# The external static library that we are linking with does not know
# how to build for this platform so we export all the flags used in
# this zephyr build to the external build system.
zephyr_get_include_directories_for_lang_as_string(C includes)
zephyr_get_system_include_directories_for_lang_as_string(C system_includes)
zephyr_get_compile_definitions_for_lang_as_string(C definitions)
zephyr_get_compile_options_for_lang_as_string(C options)

#message("C includes is: ${includes}")
#message("C system_includes is: ${system_includes}")
#message("C definitions is: ${definitions}")
#message("C options is: ${options}")

# To provide flags with west use COMMAND_LINE_FLAGS, e.g.:
# west build -b native_posix -- -DCOMMAND_LINE_FLAGS="-DVLA"
set(external_project_cflags
  "${COMMAND_LINE_FLAGS} ${includes} ${definitions} ${options} ${system_includes}"
)

include(ExternalProject)

# Add an external project to be able download and build the third
# party library. In this case downloading is not necessary as it has
# been committed to the repository.
set(src_dir ${CMAKE_CURRENT_SOURCE_DIR}/..)
set(build_dir ${CMAKE_CURRENT_BINARY_DIR}/uoscore_uedhoc)

set(LIB_TEST_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../build)
set(INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)

if(CMAKE_GENERATOR STREQUAL "Unix Makefiles")
  # https://www.gnu.org/software/make/manual/html_node/MAKE-Variable.html
  set(submake "$(MAKE)")
else() # Obviously no MAKEFLAGS. Let's hope a "make" can be found somewhere.
  set(submake "make")
endif()

message("build_dir: ${build_dir}")
message("CMAKE_CURRENT_SOURCE_DIR: ${CMAKE_CURRENT_SOURCE_DIR}")
message("CMAKE_CURRENT_BINARY_DIR: ${CMAKE_CURRENT_BINARY_DIR}")
message("LIB_TEST_LIB_DIR: ${LIB_TEST_LIB_DIR}")
message("INCLUDE_DIR: ${INCLUDE_DIR}")

ExternalProject_Add(
  oscore_edhoc_project # Name for custom target
  PREFIX ${build_dir} # Root dir for entire project
  SOURCE_DIR ${src_dir}
  BINARY_DIR ${src_dir} # This particular build system is invoked from the root
  CONFIGURE_COMMAND "" # Skip configuring the project, e.g. with autoconf
  BUILD_COMMAND
  ${submake}
  PREFIX=${build_dir}
  CC=${CMAKE_C_COMPILER}
  AR=${CMAKE_AR}
  CFLAGS=${external_project_cflags}
  INSTALL_COMMAND "" # This particular build system has no install command
  BUILD_BYPRODUCTS ${build_dir}/libuoscore-uedhoc.a
)

# Create a wrapper CMake library that our app can link with
add_library(test STATIC IMPORTED GLOBAL)
add_dependencies(
  test
  oscore_edhoc_project
)
set_target_properties(test PROPERTIES IMPORTED_LOCATION ${build_dir}/libuoscore-uedhoc.a)
target_include_directories(test INTERFACE
  ${INCLUDE_DIR}
)

target_link_libraries(app PRIVATE test)
