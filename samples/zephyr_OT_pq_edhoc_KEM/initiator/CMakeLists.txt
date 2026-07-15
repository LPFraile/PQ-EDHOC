# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(initiator)

option(USE_SUIT_2 "Enable SUIT 2" OFF)
option(USE_SUIT_7 "Enable SUIT 7" OFF)
option(USE_SUIT_12 "Enable SUIT 12" OFF)
option(USE_SUIT_14 "Enable SUIT 14" OFF)
option(USE_SUIT_15 "Enable SUIT 15" OFF)
option(USE_SUIT_18 "Enable SUIT 18" OFF)
#option(USE_X5T "Enable X5T" ON)
#option(USE_X5CHAIN "Enable X5CHAIN" OFF)
if(NOT USE_SUIT_2 AND NOT USE_SUIT_7  AND NOT USE_SUIT_12 AND NOT USE_SUIT_14 AND NOT USE_SUIT_15 AND NOT USE_SUIT_18)
  message(STATUS "No SUIT selected, defaulting to SUIT 2")
  set(USE_SUIT_2 ON)
endif()

target_include_directories(app PRIVATE ../src)
target_sources(app PRIVATE
    main.c
    ../src/coap_utils.c
    ../src/post.c
)

if(USE_SUIT_2)
FILE(GLOB app_sources 
	main.c
    ../src/coap_utils.c
    ../src/post.c
	../../../externals/zcbor/src/*.c
	../../../externals/compact25519/src/c25519/*.c
	../../../externals/compact25519/src/*.c
	../../sha256.c
	)

target_include_directories(app PRIVATE $ENV{ZEPHYR_BASE}/include)
target_include_directories(app PRIVATE 
	$ENV{ZEPHYR_BASE}/subsys/net/ip
	../src
	.
	../../common
	../../../inc
	../../../test_vectors
	../../../externals/zcbor/include 
	)
target_compile_definitions(app PRIVATE USE_SUIT_2)
#add_compile_definitions(CONFIG_COAP_CLIENT_STACK_SIZE=2024)
	#target_include_directories(app PRIVATE ${ZEPHYR_BASE}/include/)
endif()

if(USE_SUIT_7)
 if(DEFINED USE_CLEAN_IMP)
  FILE(GLOB app_sources
  main.c
  ../src/coap_utils.c
  ../src/post.c
  #edhoc_integration_tests/*.c
  ../../../externals/zcbor/src/*.c
  ../../../externals/compact25519/src/c25519/*.c
  ../../../externals/compact25519/src/*.c
  #../externals/mbedtls/library/*.c
  #../../../externals/tinycrypt/lib/source/*.c
  ../../../test_vectors/*.c
  ../../../externals/PQClean/crypto_kem/ml-kem-512/clean/*.c
  ../../../externals/PQClean/common/fips202.c
   ../../../externals/PQClean/crypto_sign/falcon-padded-512/clean/*.c
  #../../../externals/pqm4/common/randombytes.c
  #../../../externals/pqm4/mupq/common/keccakf1600.c
  #../../../externals/pqm4/common/keccakf1600.S
   #../../../externals/pqm4/mupq/common/crypto_hashblocks_sha512.c
  #../../../externals/pqm4/common/crypto_hashblocks_sha512*.*
  #../../../externals/pqm4/common/aes.*
  #../../../externals/pqm4/mupq/common/fips202.c
  )
else()
FILE(GLOB app_sources 
    main.c
    ../src/coap_utils.c
    ../src/post.c
    ../../../externals/zcbor/src/*.c
	../../../externals/compact25519/src/c25519/*.c
	../../../externals/compact25519/src/*.c
	#../../../externals/mbedtls/library/*.c
	#../../../externals/tinycrypt/lib/source/*.c
	../../../externals/pqm4/crypto_kem/kyber512/m4fstack/*.c
	../../../externals/pqm4/crypto_kem/kyber512/m4fstack/*.i
	../../../externals/pqm4/crypto_kem/kyber512/m4fstack/*.S
	#../../../externals/pqm4/crypto_sign/dilithium2/m4fstack/*.c
	#../../../externals/pqm4/crypto_sign/dilithium2/m4fstack/*.i
	#../../../externals/pqm4/crypto_sign/dilithium2/m4fstack/*.S
	#../../../externals/pqm4/crypto_sign/dilithium2/m4fstack/*.s
	../../../externals/pqm4/crypto_sign/falcon-512/m4-ct/*.c
	../../../externals/pqm4/crypto_sign/falcon-512/m4-ct/*.i
	../../../externals/pqm4/crypto_sign/falcon-512/m4-ct/*.S
	../../../externals/pqm4/crypto_sign/falcon-512/m4-ct/*.s
	../../../externals/pqm4/common/randombytes.c
	../../../externals/pqm4/common/keccakf1600.S
	../../../externals/pqm4/common/crypto_hashblocks_sha512*.*
	../../../externals/pqm4/common/aes.*
	../../../externals/pqm4/mupq/common/fips202.c)
endif()
# [FIX] Actually add the sources found by GLOB to the application target
target_sources(app PRIVATE ${app_sources})

target_include_directories(app PRIVATE $ENV{ZEPHYR_BASE}/include)
if(DEFINED USE_CLEAN_IMP)
  target_include_directories(app PRIVATE 
    $ENV{ZEPHYR_BASE}/subsys/net/ip
    .
    #../../common
	../../../inc
	../../../test_vectors
    ../../../externals/zcbor/include 
    #../externals/mbedtls/library 
    #../externals/mbedtls/include 
    #../externals/mbedtls/include/mbedtls 
    #../externals/mbedtls/include/psa
    #../../../externals/tinycrypt/lib/include
    ../../../externals/PQClean/crypto_kem/ml-kem-512/clean
    ../../../externals/PQClean/crypto_sign/falcon-padded-512/clean
    ../../../externals/PQClean/common
    ../../../externals/pqm4/libopencm3/include)
    else()
target_include_directories(app PRIVATE 
    $ENV{ZEPHYR_BASE}/subsys/net/ip
    .
	../../common
	../../../inc
	../../../test_vectors
	../../../externals/zcbor/include 
	#../../../externals/mbedtls/library 
	#../../../externals/mbedtls/include 
	#../../../externals/mbedtls/include/mbedtls 
	#../../../externals/mbedtls/include/psa
	#../../../externals/tinycrypt/lib/include
	../../../externals/pqm4/crypto_kem/kyber512/m4fstack
	#../../../externals/pqm4/common/aes.h
	../../../externals/pqm4/crypto_sign/falcon-512/m4-ct
	#../../../externals/pqm4/crypto_sign/dilithium2/m4fstack
	../../../externals/pqm4/mupq/common
	../../../externals/pqm4/libopencm3/include)
  endif()
target_compile_definitions(app PRIVATE USE_SUIT_)
#add_compile_definitions(CONFIG_COAP_CLIENT_STACK_SIZE=2024)
	#target_include_directories(app PRIVATE ${ZEPHYR_BASE}/include/)
endif()



if(USE_SUIT_12)
if(DEFINED USE_CLEAN_IMP)
  FILE(GLOB app_sources
  main.c
  ../src/coap_utils.c
  ../src/post.c
  #edhoc_integration_tests/*.c
  ../../../externals/zcbor/src/*.c
  ../../../externals/compact25519/src/c25519/*.c
  ../../../externals/compact25519/src/*.c
  #../externals/mbedtls/library/*.c
  #../../../externals/tinycrypt/lib/source/*.c
  ../../../test_vectors/*.c
  ../../../externals/PQClean/crypto_kem/ml-kem-512/clean/*.c
  ../../../externals/PQClean/common/fips202.c
   ../../../externals/PQClean/crypto_sign/ml-dsa-44/clean/*.c
  #../../../externals/pqm4/common/randombytes.c
  #../../../externals/pqm4/mupq/common/keccakf1600.c
  #../../../externals/pqm4/common/keccakf1600.S
   #../../../externals/pqm4/mupq/common/crypto_hashblocks_sha512.c
  #../../../externals/pqm4/common/crypto_hashblocks_sha512*.*
  #../../../externals/pqm4/common/aes.*
  #../../../externals/pqm4/mupq/common/fips202.c
  )
else()
FILE(GLOB app_sources 
	main.c
    ../src/coap_utils.c
    ../src/post.c
	../../../externals/zcbor/src/*.c
	../../../externals/compact25519/src/c25519/*.c
	../../../externals/compact25519/src/*.c
	#../../../externals/mbedtls/library/*.c
	../../../externals/pqm4/crypto_kem/kyber512/m4fstack/*.c
	../../../externals/pqm4/crypto_kem/kyber512/m4fstack/*.i
	../../../externals/pqm4/crypto_kem/kyber512/m4fstack/*.S
	#../../../externals/pqm4/crypto_sign/dilithium2/m4fstack/*.c
	#../../../externals/pqm4/crypto_sign/dilithium2/m4fstack/*.i
	#../../../externals/pqm4/crypto_sign/dilithium2/m4fstack/*.S
	#../../../externals/pqm4/crypto_sign/dilithium2/m4fstack/*.s
	../../../externals/pqm4/crypto_sign/dilithium2/m4fstack/*.c
	../../../externals/pqm4/crypto_sign/dilithium2/m4fstack/*.i
	../../../externals/pqm4/crypto_sign/dilithium2/m4fstack/*.S
	../../../externals/pqm4/crypto_sign/dilithium2/m4fstack/*.s
	../../../externals/pqm4/common/randombytes.c
	../../../externals/pqm4/common/keccakf1600.S
	../../../externals/pqm4/common/crypto_hashblocks_sha512*.*
	../../../externals/pqm4/common/aes.*
	../../../externals/pqm4/mupq/common/fips202.c)
endif()
target_include_directories(app PRIVATE $ENV{ZEPHYR_BASE}/include)
if(DEFINED USE_CLEAN_IMP)
  target_include_directories(app PRIVATE 
    $ENV{ZEPHYR_BASE}/subsys/net/ip
    .
    #../../common
	../../../inc
	../../../test_vectors
    ../../../externals/zcbor/include 
    #../externals/mbedtls/library 
    #../externals/mbedtls/include 
    #../externals/mbedtls/include/mbedtls 
    #../externals/mbedtls/include/psa
    #../../../externals/tinycrypt/lib/include
    ../../../externals/PQClean/crypto_kem/ml-kem-512/clean
    ../../../externals/PQClean/crypto_sign/ml-dsa-44/clean/
    ../../../externals/PQClean/common
    ../../../externals/pqm4/libopencm3/include)
    else()

target_include_directories(app PRIVATE 
	$ENV{ZEPHYR_BASE}/subsys/net/ip
	.
	../../common
	../../../inc
	../../../test_vectors
	../../../externals/zcbor/include 
	#../../../externals/mbedtls/library 
	#../../../externals/mbedtls/include 
	#../../../externals/mbedtls/include/mbedtls 
	#../../../externals/mbedtls/include/psa
	../../../externals/pqm4/crypto_kem/kyber512/m4fstack
	#../../../externals/pqm4/common/aes.h
	../../../externals/pqm4/crypto_sign/dilithium2/m4fstack
	#../../../externals/pqm4/crypto_sign/dilithium2/m4fstack
	../../../externals/pqm4/mupq/common
	../../../externals/pqm4/libopencm3/include)
endif()
target_compile_definitions(app PRIVATE USE_SUIT_12)

add_compile_definitions(CONFIG_COAP_CLIENT_STACK_SIZE=16024)
	#target_include_directories(app PRIVATE ${ZEPHYR_BASE}/include/)

endif()


if(USE_SUIT_14)
 if(DEFINED USE_CLEAN_IMP)
  FILE(GLOB app_sources
  main.c
  ../src/coap_utils.c
  ../src/post.c
  #edhoc_integration_tests/*.c
  ../../../externals/zcbor/src/*.c
  ../../../externals/compact25519/src/c25519/*.c
  ../../../externals/compact25519/src/*.c
  #../externals/mbedtls/library/*.c
  #../../../externals/tinycrypt/lib/source/*.c
  ../../../test_vectors/*.c
  ../../../externals/PQClean/crypto_kem/ml-kem-512/clean/*.c
  ../../../externals/PQClean/common/fips202.c
  ../../../externals/pqm4/mupq/crypto_sign/hawk512/ref/*.c
  #../../../externals/pqm4/common/randombytes.c
  #../../../externals/pqm4/mupq/common/keccakf1600.c
  #../../../externals/pqm4/common/keccakf1600.S
   #../../../externals/pqm4/mupq/common/crypto_hashblocks_sha512.c
  #../../../externals/pqm4/common/crypto_hashblocks_sha512*.*
  #../../../externals/pqm4/common/aes.*
  #../../../externals/pqm4/mupq/common/fips202.c
  )
else()
 FILE(GLOB app_sources
  main.c
  ../src/coap_utils.c
  ../src/post.c
  #edhoc_integration_tests/*.c
  ../../../externals/zcbor/src/*.c
  ../../../externals/compact25519/src/c25519/*.c
  ../../../externals/compact25519/src/*.c
  #../externals/mbedtls/library/*.c
  #../../../externals/tinycrypt/lib/source/*.c
  ../../../test_vectors/*.c
  ../../../externals/pqm4/crypto_kem/kyber512/m4fstack/*.c
  ../../../externals/pqm4/crypto_kem/kyber512/m4fstack/*.i
  ../../../externals/pqm4/crypto_kem/kyber512/m4fstack/*.S
  ../../../externals/pqm4/mupq/crypto_sign/hawk512/ref/*.c
  ../../../externals/pqm4/common/randombytes.c
  ../../../externals/pqm4/common/keccakf1600.S
  ../../../externals/pqm4/common/crypto_hashblocks_sha512*.*
  ../../../externals/pqm4/common/aes.*
  ../../../externals/pqm4/mupq/common/fips202.c
  )
  endif()
  target_sources(app PRIVATE ${app_sources})
  target_include_directories(app PRIVATE $ENV{ZEPHYR_BASE}/include)
  
   if(DEFINED USE_CLEAN_IMP)
  target_include_directories(app PRIVATE 
    $ENV{ZEPHYR_BASE}/subsys/net/ip
    .
    #../../common
	../../../inc
	../../../test_vectors
    ../../../externals/zcbor/include 
    #../externals/mbedtls/library 
    #../externals/mbedtls/include 
    #../externals/mbedtls/include/mbedtls 
    #../externals/mbedtls/include/psa
    #../../../externals/tinycrypt/lib/include
    ../../../externals/PQClean/crypto_kem/ml-kem-512/clean
    ../../../externals/pqm4/mupq/crypto_sign/hawk512/ref
    ../../../externals/PQClean/common
    ../../../externals/pqm4/libopencm3/include)
    else()
     target_include_directories(app PRIVATE 
    $ENV{ZEPHYR_BASE}/subsys/net/ip
    .
    #../../common
    ../../../inc
    ../../../test_vectors
    ../../../externals/zcbor/include 
    #../externals/mbedtls/library 
    #../externals/mbedtls/include 
    #../externals/mbedtls/include/mbedtls 
    #../externals/mbedtls/include/psa
    #../../../externals/tinycrypt/lib/include
    ../../../externals/pqm4/crypto_kem/kyber512/m4fstack
    ../../../externals/pqm4/mupq/crypto_sign/hawk512/ref
    ../../../externals/pqm4/mupq/common
    ../../../externals/pqm4/libopencm3/include)
   endif()  
  target_compile_definitions(app PRIVATE USE_SUIT_14)
endif()

if(USE_SUIT_15)
FILE(GLOB app_sources 
    main.c
    ../src/coap_utils.c
    ../src/post.c
    ../../../externals/zcbor/src/*.c
    ../../../externals/compact25519/src/c25519/*.c
    ../../../externals/compact25519/src/*.c
    #../../../externals/mbedtls/library/*.c
    ../../../externals/pqm4/crypto_kem/kyber512/m4fstack/*.c
    ../../../externals/pqm4/crypto_kem/kyber512/m4fstack/*.i
    ../../../externals/pqm4/crypto_kem/kyber512/m4fstack/*.S
    ../../../externals/pqm4/crypto_sign/haetae2/m4f/*.c
    ../../../externals/pqm4/crypto_sign/haetae2/m4f/*.S
    ../../../externals/pqm4/crypto_sign/haetae2/m4f/*.i
    ../../../externals/pqm4/common/randombytes.c
    ../../../externals/pqm4/common/keccakf1600.S
    ../../../externals/pqm4/common/crypto_hashblocks_sha512*.*
    ../../../externals/pqm4/common/aes.*
    ../../../externals/pqm4/mupq/common/fips202.c)

target_include_directories(app PRIVATE $ENV{ZEPHYR_BASE}/include)
target_include_directories(app PRIVATE 
    $ENV{ZEPHYR_BASE}/subsys/net/ip
    .
    ../../common
    ../../../inc
    ../../../test_vectors
    ../../../externals/zcbor/include 
    #../../../externals/mbedtls/library 
    #../../../externals/mbedtls/include 
    #../../../externals/mbedtls/include/mbedtls 
    #../../../externals/mbedtls/include/psa
    ../../../externals/pqm4/crypto_kem/kyber512/m4fstack
    ../../../externals/pqm4/crypto_sign/haetae2/m4f
    ../../../externals/pqm4/mupq/common
    ../../../externals/pqm4/libopencm3/include)

# CRITICAL FIX: Add these definitions so buffer_sizes.h allocates enough memory
add_compile_definitions(PQM4 KYBER_LEVEL_1 HAETAE_LEVEL_2 MUPQ)
target_compile_definitions(app PRIVATE USE_SUIT_15)
#add_compile_definitions(CONFIG_COAP_CLIENT_STACK_SIZE=2024)
    #target_include_directories(app PRIVATE ${ZEPHYR_BASE}/include/)
endif()
if(USE_SUIT_18)
 if(DEFINED USE_CLEAN_IMP)
  FILE(GLOB app_sources
  main.c
  ../src/coap_utils.c
  ../src/post.c
  #edhoc_integration_tests/*.c
  ../../../externals/zcbor/src/*.c
  ../../../externals/compact25519/src/c25519/*.c
  ../../../externals/compact25519/src/*.c
  #../externals/mbedtls/library/*.c
  #../../../externals/tinycrypt/lib/source/*.c
  ../../../test_vectors/*.c
  ../../../externals/PQClean/crypto_kem/ml-kem-512/clean/*.c
	../../../externals/PQClean/common/fips202.c
  #../../../externals/pqm4/common/randombytes.c
   # ../../../externals/pqm4/mupq/common/keccakf1600.c
  #../../../externals/pqm4/common/keccakf1600.S
  # ../../../externals/pqm4/mupq/common/crypto_hashblocks_sha512.c
  #../../../externals/pqm4/common/crypto_hashblocks_sha512*.*
  #../../../externals/pqm4/common/aes.*
  #../../../externals/pqm4/mupq/common/fips202.c
  )
else()
FILE(GLOB app_sources 
    main.c
    ../src/coap_utils.c
    ../src/post.c
    ../../../externals/zcbor/src/*.c
	../../../externals/compact25519/src/c25519/*.c
	../../../externals/compact25519/src/*.c
	#../../../externals/mbedtls/library/*.c
	#../../../externals/tinycrypt/lib/source/*.c
	../../../externals/pqm4/crypto_kem/kyber512/m4fstack/*.c
	../../../externals/pqm4/crypto_kem/kyber512/m4fstack/*.i
	../../../externals/pqm4/crypto_kem/kyber512/m4fstack/*.S
	../../../externals/pqm4/common/randombytes.c
	../../../externals/pqm4/common/keccakf1600.S
	../../../externals/pqm4/common/crypto_hashblocks_sha512*.*
	../../../externals/pqm4/common/aes.*
	../../../externals/pqm4/mupq/common/fips202.c)
endif()
# [FIX] Actually add the sources found by GLOB to the application target
target_sources(app PRIVATE ${app_sources})

target_include_directories(app PRIVATE $ENV{ZEPHYR_BASE}/include)
if(DEFINED USE_CLEAN_IMP)
  target_include_directories(app PRIVATE 
    $ENV{ZEPHYR_BASE}/subsys/net/ip
    .
    #../../common
	../../../inc
	../../../test_vectors
    ../../../externals/zcbor/include 
    #../externals/mbedtls/library 
    #../externals/mbedtls/include 
    #../externals/mbedtls/include/mbedtls 
    #../externals/mbedtls/include/psa
    #../../../externals/tinycrypt/lib/include
    ../../../externals/PQClean/crypto_kem/ml-kem-512/clean
	../../../externals/PQClean/common
    #../../../externals/pqm4/mupq/common
    ../../../externals/pqm4/libopencm3/include)
else()
target_include_directories(app PRIVATE 
    $ENV{ZEPHYR_BASE}/subsys/net/ip
    .
	../../common
	../../../inc
	../../../test_vectors
	../../../externals/zcbor/include 
	#../../../externals/mbedtls/library 
	#../../../externals/mbedtls/include 
	#../../../externals/mbedtls/include/mbedtls 
	#../../../externals/mbedtls/include/psa
	#../../../externals/tinycrypt/lib/include
	../../../externals/pqm4/crypto_kem/kyber512/m4fstack
	#../../../externals/pqm4/common/aes.h
	../../../externals/pqm4/mupq/common
	../../../externals/pqm4/libopencm3/include)
endif()
target_compile_definitions(app PRIVATE USE_SUIT_18)
#add_compile_definitions(CONFIG_COAP_CLIENT_STACK_SIZE=2024)
	#target_include_directories(app PRIVATE ${ZEPHYR_BASE}/include/)
endif()

# [FIX] Add this block to ensure sources are compiled, matching the working sample
target_sources(app PRIVATE ${app_sources})

#target_sources(app PRIVATE ${app_sources}
#    main.c
#    ../src/coap_utils.c
#    ../src/post.c
#)
#target_sources(app PRIVATE ${ZEPHYR_BASE}/subsys/net/lib/coap/coap_client.c)
#target_sources(app PRIVATE ${ZEPHYR_BASE}/subsys/net/lib/coap/coap.c)

add_definitions(
	#-DMBEDTLS_CONFIG_FILE="mbedtls_config_uoscore_uedhoc.h"
	-DDEBUG_PRINT
	-DZCBOR_CANONICAL
	#-DUSE_X5CHAIN
	#-DKYBER_LEVEL_1
	#-DFALCON_LEVEL_1
)

if(DEFINED USE_X5CAHIN)
  add_definitions(-DUSE_X5CHAIN=${USE_X5CHAIN})
  message(STATUS "USE_X5CHAIN is defined")
 # add_compile_definitions(CONFIG_BT_RX_STACK_SIZE=3024)

elseif(DEFINED USE_X5T)
  add_definitions(-DUSE_X5T=${USE_X5T})
  #add_compile_definitions(CONFIG_BT_RX_STACK_SIZE=2024) 
  message(STATUS "USE_X5T is defined")
endif()


if(DEFINED POWER_MEASUREMENTS)
add_definitions(-DPOWER_MEASUREMENTS=${POWER_MEASUREMENTS})
endif()

if(DEFINED USE_CLEAN_IMP)
  add_definitions(-DUSE_CLEAN_IMP=${USE_CLEAN_IMP})
  message(STATUS "USE_CLEAN_IMP is defined")
endif()
#if(USE_X5CHAIN)
#add_definitions(
#	-DMBEDTLS_CONFIG_FILE="mbedtls_config_uoscore_uedhoc.h"
	#-DDEBUG_PRINT
#	-DZCBOR_CANONICAL
#	-DUSE_X5CHAIN
	#-DKYBER_LEVEL_1
	#-DFALCON_LEVEL_1
#)
#dd_compile_definitions(CONFIG_BT_RX_STACK_SIZE=3024)
#elseif(USE_X5T)
#add_definitions(
#	-DMBEDTLS_CONFIG_FILE="mbedtls_config_uoscore_uedhoc.h"
	#-DDEBUG_PRINT
#	-DZCBOR_CANONICAL
	#-DKYBER_LEVEL_1
	#-DFALCON_LEVEL_1
#	-DUSE_X5T
#)
#add_compile_definitions(CONFIG_BT_RX_STACK_SIZE=2024)
#endif()


#add_compile_definitions(CONFIG_COAP_CLIENT=y)
#add_compile_definitions(CONFIG_COAP_CLIENT_BLOCK_SIZE=512)
#add_compile_definitions(CONFIG_COAP_CLIENT_MESSAGE_SIZE=512)
#add_compile_definitions(CONFIG_COAP_CLIENT_MESSAGE_HEADER_SIZE=48)
#add_compile_definitions(CONFIG_COAP_CLIENT_THREAD_PRIORITY=2)
#add_compile_definitions(CONFIG_COAP_LOG_LEVEL=1)
#add_compile_definitions(CONFIG_BT_LOG_LEVEL=1)
#add_compile_definitions(CONFIG_NET_SOCKETS_POSIX_NAMES=y)
#add_compile_definitions(CONFIG_COAP_INIT_ACK_TIMEOUT_MS=20000)
#add_compile_definitions(CONFIG_COAP_CLIENT_STACK_SIZE=2024)
#add_compile_definitions(CONFIG_BT_RX_STACK_SIZE=2024)


# The external static library that we are linking with does not know
# how to build for this platform so we export all the flags used in
# this zephyr build to the external build system.
zephyr_get_include_directories_for_lang_as_string(       C includes)
zephyr_get_system_include_directories_for_lang_as_string(C system_includes)
zephyr_get_compile_definitions_for_lang_as_string(       C definitions)
zephyr_get_compile_options_for_lang_as_string(           C options)

set(external_project_cflags
  "${includes} ${definitions} ${options} ${system_includes}"
  )
include(${ZEPHYR_BASE}/samples/net/common/common.cmake)
include(ExternalProject)

# Add an external project to be able download and build the third
# party library. In this case downloading is not necessary as it has
# been committed to the repository.
set(src_dir   ${CMAKE_CURRENT_SOURCE_DIR}/../../..)
set(build_dir ${CMAKE_CURRENT_BINARY_DIR}/uoscore_uedhoc)

set(LIB_TEST_LIB_DIR     ${CMAKE_CURRENT_SOURCE_DIR}/../build)
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
  oscore_edhoc_project                 # Name for custom target
  PREFIX ${build_dir} # Root dir for entire project
  SOURCE_DIR ${src_dir}
  BINARY_DIR ${src_dir} # This particular build system is invoked from the root
  CONFIGURE_COMMAND ""    # Skip configuring the project, e.g. with autoconf
  BUILD_COMMAND
  ${submake}
  PREFIX=${build_dir}
  CC=${CMAKE_C_COMPILER}
  AR=${CMAKE_AR}
  CFLAGS=${external_project_cflags}
  INSTALL_COMMAND ""      # This particular build system has no install command
  BUILD_BYPRODUCTS ${build_dir}/libuoscore-uedhoc.a
  )

# Create a wrapper CMake library that our app can link with
add_library(test STATIC IMPORTED GLOBAL)
add_dependencies(
	test
	oscore_edhoc_project)

set_target_properties(test PROPERTIES IMPORTED_LOCATION 
	${build_dir}/libuoscore-uedhoc.a)

target_include_directories(test INTERFACE
	${INCLUDE_DIR})

target_link_libraries(app PRIVATE test)


