# PQ EDHOC Linux samples proposal 1: 

This example runs the first PQ proposal for EDHOC that use KEMs for session key derivations and PQ signature for authentication. It use method 0 and PQ ciphersuits 
This folder contains two samples intended to be executed on a Linux host

* initiator - PQ EDHOC initiator running on top of a CoAP client
* responder - PQ EDHOC responder running on top of a CoAP server

## Dependencies on Other Software Components 
[liboqs](https://github.com/open-quantum-safe/liboqs) - An open source C library for quantum-safe cryptographic algorithms.

### PQ KEMs algortithm
The PQ KEMs that are going to be used must be selected on the makefile_config.mk file in order to reserve the smaller necessary buffers. Behind a list of available KEMs until the date.  
#### KYBER 512
- FEATURES += -DKYBER_LEVEL_1
#### KYBER 768   
-  FEATURES += -DKYBER_LEVEL_3
#### HQC 128 
- FEATURES += -DHQC_LEVEL_1

### PQ Signature algorithms
The PQ signature algorithms that are going to be used must be selected on the makefile_config.mk file in order to reserve the smaller necessary buffers. Behind a list of available signatures until the date.
#### FALCON 512
- FEATURES += -DFALCON_LEVEL_1

## Extra PQ Cipher Suites add it (isi-embedded group)
| 7    | AES-CCM-16-64-128, SHA-256,8, KYBER_LEVEL_1, FALCON_LEVEL_1, AES-CCM-16-64-128, SHA-256 |
| 8    | AES-CCM-16-128-128, SHA-256, 16,
KYBER_LEVEL_1, FALCON_LEVEL_1,  AES-CCM-16-64-128, SHA-256 |
| 9    | AES-CCM-16-128-128, SHA-256, 16,
KYBER_LEVEL_3, FALCON_LEVEL_1,  AES-CCM-16-64-128, SHA-256 |
| 10    | AES-CCM-16-128-128, SHA-256, 16,
KYBER_LEVEL_1, FALCON_PADDED_LEVEL_1,  AES-CCM-16-64-128, SHA-256 |
| 11    | AES-CCM-16-128-128, SHA-256, 16, HQS_LEVEL1, FALCONLEVEL_1, AES-CCM-16-64-128, SHA-256 |

The initiator and responder must be pre-selected with the ciphersuit that will be ussing on the EDHOC session. The test vectors are setting with the necessary information at test_vectors/edhoc_test_vectors_p256_v16.h file

### Cipher suite 7:
- FEATURES += -DKYBER_LEVEL_1
- FEATURES += -DFALCON_LEVEL_1
#### TEST_VECTOR_8 with SUITES_7 
- ID_CRED_X = Kid
- CRED_X = X509 FALCON 512 certificate

### Cipher suite 8:
- FEATURES += -DKYBER_LEVEL_1
- FEATURES += -DFALCON_LEVEL_1
#### TEST_VECTOR_8 with SUITES_8
- ID_CRED_X = Kid
- CRED_X = X509 FALCON 512 certificate

## Cipher suite 9:
- FEATURES += -DKYBER_LEVEL_3
- FEATURES += -DFALCON_LEVEL_1
#### TEST_VECTOR_8 with SUITES_9
- ID_CRED_X = Kid
- CRED_X = X509 FALCON 512 certificate

## Cipher suite 9:
- FEATURES += -DKYBER_LEVEL_1
- FEATURES += -DFALCON_PADDED_LEVEL_1
#### TEST_VECTOR_8 with SUITES_10
- ID_CRED_X = Kid
- CRED_X = X509 FALCON 512 certificate

## Cipher suite 11:
- FEATURES += -DHQS_LEVEL_1
- FEATURES += -DFALCON_PADDED_LEVEL_1
#### TEST_VECTOR_8 with SUITES_11
- ID_CRED_X = Kid
- CRED_X = X509 FALCON 512 certificate

