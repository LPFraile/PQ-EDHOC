# Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
# file at the top-level directory of this distribution.

# Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
# http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
# <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
# option. This file may not be copied, modified, or distributed
# except according to those terms.

LIB_NAME = libuoscore-uedhoc.a

include makefile_config.mk

$(info    CC is $(CC))
# $(info    LIB_NAME is $(LIB_NAME))
# $(info    PREFIX is $(PREFIX))
# $(info    SOURCE_DIR is $(SOURCE_DIR))
# $(info    BINARY_DIR is $(BINARY_DIR))
# $(info    CC is $(CC))
# $(info    CFLAGS is $(CFLAGS))
# $(info    OPT is $(OPT))
# $(info    CRYPTO_ENGINE is $(CRYPTO_ENGINE))
################################################################################
# Build directory
PREFIX ?= build
DIR = $(PREFIX)
$(shell mkdir -p $(DIR))
################################################################################
# C Source files

C_SOURCES += $(wildcard src/edhoc/*.c)
C_SOURCES += $(wildcard src/oscore/*.c)
C_SOURCES += $(wildcard src/common/*.c)
C_SOURCES += $(wildcard src/cbor/*.c)


#$(info    \n C_SOURCES is $(C_SOURCES))
vpath %.c $(sort $(dir $(C_SOURCES)))

################################################################################
# CFLAGS
################################################################################
FILTERED_CFLAGS = -Os
EXTENDED_CFLAGS = $(filter-out $(FILTERED_CFLAGS), $(CFLAGS))

#add options form configuration file 
EXTENDED_CFLAGS += $(FEATURES)
EXTENDED_CFLAGS += $(FEATURES)
EXTENDED_CFLAGS += $(ARCH)
EXTENDED_CFLAGS += $(OPT)
EXTENDED_CFLAGS += $(DEBUG_PRINT)
EXTENDED_CFLAGS += $(CBOR_ENGINE)
EXTENDED_CFLAGS += $(OSCORE_NVM_SUPPORT)
EXTENDED_CFLAGS += $(CRYPTO_ENGINE)
EXTENDED_CFLAGS += $(UNIT_TEST)

# Unit tests require NVM support regardless of user settings
ifeq ($(findstring UNIT_TEST,$(DUNIT_TEST)),UNIT_TEST)
EXTENDED_CFLAGS += -DOSCORE_NVM_SUPPORT
endif

#EXTENDED_CFLAGS += -g
#generate debug symbols
#EXTENDED_CFLAGS += -g3 -gdwarf-4

# Generate dependency information
#EXTENDED_CFLAGS += -MMD -MP -MF"$(@:%.o=%.d)"

# Generate stack usage information
#EXTENDED_CFLAGS += -fstack-usage

# use C11
#EXTENDED_CFLAGS += -std=c11 NO different in processing time in kems
EXTENDED_CFLAGS += -std=c99
#EXTENDED_CFLAGS += -Wl,--wrap=uECC_make_key_with_d
#reduce very little (500 CLKS) and give me bigger size ram to 73.75% from 53%
#EXTENDED_CFLAGS += -flto 
#EXTENDED_CFLAGS += -finline-functions
#EXTENDED_CFLAGS += -ffunction-sections
#EXTENDED_CFLAGS += -fdata-sections



#GCC warning flags
ifeq ($(findstring cc,$(CC)),cc)
#EXTENDED_CFLAGS += -Waddress
#EXTENDED_CFLAGS += -Waggregate-return
#EXTENDED_CFLAGS += -Wformat-nonliteral
#EXTENDED_CFLAGS += -Wformat-security
#EXTENDED_CFLAGS += -Wformat
#EXTENDED_CFLAGS += -Winit-self
#EXTENDED_CFLAGS += -Wmissing-include-dirs
#EXTENDED_CFLAGS += -Wno-multichar
#EXTENDED_CFLAGS += -Wno-parentheses
#EXTENDED_CFLAGS += -Wno-type-limits
#EXTENDED_CFLAGS += -Wno-unused-parameter
#EXTENDED_CFLAGS += -Wunreachable-code
#EXTENDED_CFLAGS += -Wwrite-strings
#EXTENDED_CFLAGS += -Wpointer-arith
#EXTENDED_CFLAGS += -Wall
#EXTENDED_CFLAGS += -Wextra
#EXTENDED_CFLAGS += -Wcast-qual
#EXTENDED_CFLAGS += -Wstack-usage=9000
#EXTENDED_CFLAGS += -Wconversion
#EXTENDED_CFLAGS += -Wpedantic
#EXTENDED_CFLAGS += -Wno-error

#Clang warning flags
else ifeq ($(findstring clang,$(CC)),clang)
EXTENDED_CFLAGS += -Wcast-qual
EXTENDED_CFLAGS += -Wconversion
EXTENDED_CFLAGS += -Wexit-time-destructors
EXTENDED_CFLAGS += -Wglobal-constructors
EXTENDED_CFLAGS += -Wmissing-noreturn
EXTENDED_CFLAGS += -Wmissing-prototypes
EXTENDED_CFLAGS += -Wno-missing-braces
EXTENDED_CFLAGS += -Wold-style-cast
EXTENDED_CFLAGS += -Wshadow
EXTENDED_CFLAGS += -Wweak-vtables
EXTENDED_CFLAGS += -Wall
EXTENDED_CFLAGS += -Wextra
EXTENDED_CFLAGS += -Wpedantic
EXTENDED_CFLAGS += -Wstack-exhausted
EXTENDED_CFLAGS += -Wconversion
#EXTENDED_CFLAGS += -Werror
endif

ifeq ($(findstring ASAN,$(ASAN)),ASAN)
EXTENDED_CFLAGS += -fsanitize=address -fomit-frame-pointer
endif

ifeq ($(findstring ASAN,$(ASAN)),ASAN)
EXTENDED_CFLAGS += -fsanitize=address -fomit-frame-pointer
endif

################################################################################
# C includes
################################################################################
# Set a default crypto engine if non is provided in CRYPTO_ENGINE or CC
ifneq ($(findstring TINYCRYPT,$(EXTENDED_CFLAGS)),TINYCRYPT) 
ifneq ($(findstring MBEDTLS,$(EXTENDED_CFLAGS)),MBEDTLS) 
EXTENDED_CFLAGS += -DTINYCRYPT
endif
endif

C_INCLUDES += -Iinc

# Crypto engine
ifeq ($(findstring COMPACT25519,$(EXTENDED_CFLAGS)),COMPACT25519) 
C_INCLUDES += -Iexternals/compact25519/src/c25519/ 
C_INCLUDES += -Iexternals/compact25519/src/ 
endif

ifeq ($(findstring TINYCRYPT,$(EXTENDED_CFLAGS)),TINYCRYPT)
C_INCLUDES += -Iexternals/tinycrypt/lib/include
endif
 
ifeq ($(findstring MBEDTLS,$(EXTENDED_CFLAGS)),MBEDTLS)
C_INCLUDES += -Iexternals/mbedtls/library 
C_INCLUDES += -Iexternals/mbedtls/include 
C_INCLUDES += -Iexternals/mbedtls/include/mbedtls 
C_INCLUDES += -Iexternals/mbedtls/include/psa 
endif

# CBOR engine
ifeq ($(findstring ZCBOR,$(EXTENDED_CFLAGS)),ZCBOR)
C_INCLUDES += -Iexternals/zcbor/include
endif

ifeq ($(findstring LIBOQS,$(EXTENDED_CFLAGS)),LIBOQS)
C_INCLUDES += -Iexternals/liboqs/build/include
# Path to the external static library
EXTERNAL_LIB_PATH = externals/liboqs/build/lib
EXTERNAL_STATIC_LIB = liboqs.a
endif

ifeq ($(findstring PQM4,$(EXTENDED_CFLAGS)),PQM4)
C_INCLUDES += -Iexternals/pqm4/common
#C_INCLUDES += -Iexternals/pqm4/mupq/common
#C_INCLUDES += -Iexternals/pqm4/mupq/pqclean/common
ifeq ($(findstring KYBER_LEVEL_1,$(EXTENDED_CFLAGS)),KYBER_LEVEL_1)
C_INCLUDES += -Iexternals/pqm4/crypto_kem/kyber512/m4fstack
endif
ifeq ($(findstring KYBER_LEVEL_3,$(EXTENDED_CFLAGS)),KYBER_LEVEL_3)
C_INCLUDES += -Iexternals/pqm4/crypto_kem/kyber768/m4fstack
endif
ifeq ($(findstring BIKE_LEVEL_1,$(EXTENDED_CFLAGS)),BIKE_LEVEL_1)
C_INCLUDES += -Iexternals/pqm4/crypto_kem/bikel1/m4f
endif
ifeq ($(findstring HQC_LEVEL_1,$(EXTENDED_CFLAGS)),HQC_LEVEL_1)
C_INCLUDES += -Iexternals/PQClean/crypto_kem/hqc-128/clean
endif
#C_INCLUDES += -Iexternals/pqm4/crypto_sign/dilithium2/m4fstack
ifeq ($(findstring FALCON_LEVEL_1,$(EXTENDED_CFLAGS)),FALCON_LEVEL_1)
C_INCLUDES += -Iexternals/pqm4/crypto_sign/falcon-512/m4-ct
endif
ifeq ($(findstring DILITHIUM_LEVEL_2,$(EXTENDED_CFLAGS)),DILITHIUM_LEVEL_2)
C_INCLUDES += -Iexternals/pqm4/crypto_sign/dilithium2/m4fstack
#C_INCLUDES += -Iexternals/pqm4/crypto_sign/dilithium2/m4f
endif
ifeq ($(findstring DHAWK_LEVEL_1,$(EXTENDED_CFLAGS)),DHAWK_LEVEL_1)
#C_INCLUDES += -Iexternals/pqm4/crypto_sign/dilithium2/m4fstack
C_INCLUDES += -Iexternals/pqm4/mupq/crypto_sign/hawk512/ref
endif
ifeq ($(findstring DHAETAE_LEVEL_2,$(EXTENDED_CFLAGS)),DHAETAE_LEVEL_2)
#C_INCLUDES += -Iexternals/pqm4/crypto_sign/dilithium2/m4fstack
C_INCLUDES += -Iexternals/pqm4/crypto_sign/haetae2/m4f
endif

ifeq ($(findstring DOV_IP_LEVEL_1,$(EXTENDED_CFLAGS)),DOV_IP_LEVEL_1)
#C_INCLUDES += -Iexternals/pqm4/crypto_sign/dilithium2/m4fstack
C_INCLUDES += -Iexternals/pqm4/crypto_sign/ov-Ip/m4f
endif


C_INCLUDES += -Iexternals/pqm4/libopencm3/include
endif

ifneq ($(findstring PQM4,$(EXTENDED_CFLAGS)),PQM4)
ifeq ($(findstring MUPQ,$(EXTENDED_CFLAGS)),MUPQ)
C_INCLUDES += -Iexternals/pqm4/mupq/common
ifeq ($(findstring DHAWK_LEVEL_1,$(EXTENDED_CFLAGS)),DHAWK_LEVEL_1)
C_INCLUDES += -Iexternals/pqm4/mupq/crypto_sign/hawk512/ref
endif
ifeq ($(findstring DHAETAE_LEVEL_2,$(EXTENDED_CFLAGS)),DHAETAE_LEVEL_2)
C_INCLUDES += -Iexternals/pqm4/mupq/crypto_sign/haetae2/ref
endif
endif
endif

#add include paths
EXTENDED_CFLAGS += $(C_INCLUDES)



$(info    EXTENDED_CFLAGS are $(EXTENDED_CFLAGS))
################################################################################
# build the library
################################################################################
OBJ = $(addprefix $(DIR)/,$(notdir $(C_SOURCES:.c=.o)))
#$(info    \n OBJ is $(OBJ))

ifeq ($(findstring LIBOQS,$(EXTENDED_CFLAGS)),LIBOQS)
$(DIR)/$(LIB_NAME): $(OBJ) $(EXTERNAL_LIB_PATH)/$(EXTERNAL_STATIC_LIB)
	@echo "[Link (Static)]"
	@$(AR) -rcs $@ $^

$(DIR)/%.o: %.c Makefile makefile_config.mk
	@echo [Compile] $<
	@$(CC) -c $(EXTENDED_CFLAGS)  $< -o $@ -L$(EXTERNAL_LIB_PATH) -loqs
endif
ifneq ($(findstring LIBOQS,$(EXTENDED_CFLAGS)),LIBOQS)
$(DIR)/$(LIB_NAME): $(OBJ) 
	@echo "[Link (Static)]"
	@$(AR) -rcs $@ $^

$(DIR)/%.o: %.c Makefile makefile_config.mk
	@echo [Compile] $<
	@$(CC) -c $(EXTENDED_CFLAGS)  $< -o $@ 
endif
clean:
	rm -fR $(DIR)
