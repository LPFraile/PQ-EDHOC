################################################################################
# Toolchain
################################################################################
#CC = gcc
#AR = ar
#CC = /opt/arm-gnu-toolchain-12.2.rel1-x86_64-arm-none-eabi/bin/arm-none-eabi-gcc
#AR = /opt/arm-gnu-toolchain-12.2.rel1-x86_64-arm-none-eabi/bin/arm-none-eabi-ar
#CC = clang-13


################################################################################
# Architecture
################################################################################
# see for arm flags: https://gcc.gnu.org/onlinedocs/gcc/ARM-Options.html
#ARCH = -m32
#ARCH = -mtune=cortex-m3


################################################################################ 
# Compiler optimization
################################################################################ 
OPT = -Os


################################################################################
# Print helpful debug messages
################################################################################
DEBUG_PRINT += -DDEBUG_PRINT

################################################################################
# Use Address Sanitizer, e.g. with native_posix
################################################################################
#ASAN += -DASAN

################################################################################
# Unit testing
################################################################################
# Uncomment this to enable building the unit tests
#UNIT_TEST += -DUNIT_TEST


################################################################################
# CBOR engine
################################################################################
# currently only ZCBOR is supported
CBOR_ENGINE += -DZCBOR

# Uncomment to enable Non-volatile memory (NVM) support for storing security context between device reboots
OSCORE_NVM_SUPPORT += -DOSCORE_NVM_SUPPORT

################################################################################
# RAM optimization
################################################################################
# Compute the length of buffers at runtime (variable length array VLA)
# Please note that: we do not support this feature under Windows with MSVC (lack of support for VLA).
#FEATURES += -DVLA

################################################################################
# RAM optimization EDHOC
################################################################################
# In deployments where no protected application message is sent from the 
# Responder to the Initiator, message_4 MUST be used.
# FEATURES += -DMESSAGE_4

# If EAD is not used set its buffer size to 0
FEATURES += -DEAD_SIZE=0

# Size of the connection identifier of the initiator C_I
FEATURES += -DC_I_SIZE=1

# Size of the connection identifier of the initiator C_R
FEATURES += -DC_R_SIZE=1

# # Size of ID_CRED_R
# FEATURES += -DID_CRED_R_SIZE=2960

# # Size of ID_CRED_I
# FEATURES += -DID_CRED_I_SIZE=2960


# Number of supported suites by the initiator
FEATURES += -DSUITES_I_SIZE=1 

################################################################################
# Select for use EDHOC DH algorithm
FEATURES += -DDH

################################################################################
# Select the PQ KEM algorithm to be used, 
#FEATURES += -DKYBER_LEVEL_1
#FEATURES += -DKYBER_LEVEL_3
#FEATURES += -DHQC_LEVEL_1 
#FEATURES += -DBIKE_LEVEL_1

################################################################################
# Select the PQ Signature algorithm to be used
#FEATURES += -DFALCON_LEVEL_1

#FEATURES += -DDILITHIUM_LEVEL_2
#FEATURES += -DHAWK_LEVEL_1
#FEATURES += -DHAETAE_LEVEL_2

################################################################################
# Select for use X5CHAIN credentials instead of by default X5T
#FEATURES += -DUSE_X5CHAIN


###############################################################
# Select block wise transfer block size 
#  The maximum block size a server supports.  Can be 0
# (reset), or must be  32, 64, 128, 256, 512 or 1024.
FEATURES += -DUSE_COAP_BLOCK_SIZE=512

##################################################################
# Define to use TCP. By default it use UDP 
#FEATURES += -DUSE_TCP 




################################################################################
# RAM optimization OSCORE
################################################################################
# Max size of an OSCORE plaintext
FEATURES += -DOSCORE_MAX_PLAINTEXT_LEN=1024

# Max size of the E options buffer
FEATURES += -DE_OPTIONS_BUFF_MAX_LEN=100

# Max size of the I options buffer
FEATURES += -DI_OPTIONS_BUFF_MAX_LEN=100


################################################################################
# Crypto engine
################################################################################
# The uoscore-uedhoc can be used with different crypto engines. 
# The user can provide as well additional crypto engines by providing 
# implementations of the function defined (as weak) in the crypto_wrapper file.
# Currently we have build in support for the following engines which 
# allow fowling modes of operation and suites:
#
# EDHOC suites: 
# Value: 0
#    Array: 10, -16, 8, 4, -8, 10, -16
#    Desc: AES-CCM-16-64-128, SHA-256, 8, X25519, EdDSA,
#          AES-CCM-16-64-128, SHA-256

#    Value: 1
#    Array: 30, -16, 16, 4, -8, 10, -16
#    Desc: AES-CCM-16-128-128, SHA-256, 16, X25519, EdDSA,
#          AES-CCM-16-64-128, SHA-256

#    Value: 2
#    Array: 10, -16, 8, 1, -7, 10, -16
#    Desc: AES-CCM-16-64-128, SHA-256, 8, P-256, ES256,
#          AES-CCM-16-64-128, SHA-256

#    Value: 3
#    Array: 30, -16, 16, 1, -7, 10, -16
#    Desc: AES-CCM-16-128-128, SHA-256, 16, P-256, ES256,
#          AES-CCM-16-64-128, SHA-256

#    Value: 4
#    Array: 24, -16, 16, 4, -8, 24, -16
#    Desc: ChaCha20/Poly1305, SHA-256, 16, X25519, EdDSA,
#          ChaCha20/Poly1305, SHA-256

# EDHOC methods: 
# +-------+-------------------+-------------------+-------------------+
# | Value | Initiator         | Responder         | Reference         |
# +-------+-------------------+-------------------+-------------------+
# |     0 | Signature Key     | Signature Key     | [[this document]] |
# |     1 | Signature Key     | Static DH Key     | [[this document]] |
# |     2 | Static DH Key     | Signature Key     | [[this document]] |
# |     3 | Static DH Key     | Static DH Key     | [[this document]] |
# +-------+-------------------+-------------------+-------------------+
#
#
#
# +--------+---------+---------+-------------------------------------------
# protocol | suite   | method  | ENGINE
# +--------+---------+---------+-------------------------------------------
# | OSCORE |         |         | TINYCRYPT or MBEDTLS
# | EDHOC  | 0/1     | 0/1/2   | COMPACT25519 with (TINYCRYPT or MBEDTLS)
# | EDHOC  | 0/1     | 3       | MBEDTLS or (COMPACT25519 with TINYCRYPT)
# | EDHOC  | 2/3     | 0/1/2/3 | MBEDTLS
# | EDHOC  | 0/1/2/3 | 0/1/2/3 | MBEDTLS and COMPACT25519
# | EDHOC  | -22     | 0       | LIBOQS and TINYCRYPT

#CRYPTO_ENGINE += -DPQM4
CRYPTO_ENGINE += -DTINYCRYPT
CRYPTO_ENGINE += -DCOMPACT25519
###############################################################
# Enable only when we use HQC KEM
#CRYPTO_ENGINE += -DPQCLEAN
#CRYPTO_ENGINE += -DMBEDTLS
################################################################
# Enable that for PQ tests in linux
#CRYPTO_ENGINE += -DLIBOQS
###############################################################
# Enable only for HAWK and HAETAE in linux

#CRYPTO_ENGINE += -DMUPQ 


