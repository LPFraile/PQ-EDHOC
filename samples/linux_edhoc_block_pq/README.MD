# PQ EDHOC Linux samples proposal 1: 

This example runs the first PQ proposal for EDHOC that use KEMs for session key derivations and PQ signature for authentication. It use method 0 and PQ ciphersuits 
This folder contains two samples intended to be executed on a Linux host

* initiator - PQ EDHOC initiator running on top of a CoAP client with Block Wise Transfer
* responder - PQ EDHOC responder running on top of a CoAP server with Block Wise Transfer

The repo contains submodules. Git clone with --recurse submodule option

## Dependencies on Other Software Components 
[libcoap](https://github.com/obgm/libcoap) - C implementation of a lightweight application-protocol for devices that are constrained their resources such as computing power, RF range, memory, bandwidth, or network packet sizes. This protocol, CoAP, is standardized by the IETF as RFC 7252.

 - cmake -E remove_directory build
 - cmake -E make_directory build
 - cd build
 - cmake .. -DENABLE_DTLS=OFF
 - cmake --build .
 - [sudo] cmake --build . -- install

[liboqs](https://github.com/open-quantum-safe/liboqs) - An open source C library for quantum-safe cryptographic algorithms.
This library need to be compile without openssl. Following the next steps
 - mkdir build
 - cd build
 - cmake -G Ninja .. -DOQS_USE_OPENSSL=OFF
 - Ninja
## TRANSPORT LAYER CONFIGURATION
At compile time you need to chose what transport layer to use TCP or UDP. By default UDP is selected. To use TCP the following macro must be definded in the Makefile_config.mk file.
- FEATURES += -DUSE_TCP 

## COAP BLOCK WISE TRANSFER CONFIGURATION
The coap client and server are setting to works with block wise transfer. The block size support must be chosed at compile time.  Can be 0(reset), or must be  32, 64, 128, 256, 512 or 1024. It is configure at compilation time by define the folowing macro.
- FEATURES += -DUSE_COAP_BLOCK_SIZE=512 

Optionally can be chosen three diferent paramete to manage the retransmisions when the transport layers is setting to TCP. This must be selected in the Initiator/src/main.c code.

### Maximum number of retransmisions
If not define by default is 4
- #define COAP_SESSION_MAX_RET 4 

### ACK second response
Number of seconds when to expect an ACK or a response to an outstanding CON message. If not define by default is 2 seconds
- #define COAP_SESSION_ACK_TIMEOUT_INT 2  /**< Integer part of fixed point variable */
- #define COAP_SESSION_ACK_TIMEOUT_FRA 0 /**< Fractional part of fixed point variable 1/1000 (3 points) precision */

### ACK random factor 
A factor that is used to randomize the wait time before a message is retransmitted to prevent synchronization effects. Default value of ACK_RANDOM_FACTOR is 1.5
- #define COAP_SESSION_ACK_RANDOM_FACTOR_INT 1 /**< Integer part of fixed point variable */
- #define COAP_SESSION_ACK_RANDOM_FACTOR_FRA 5 /**< Fractional part of fixed point variable 1/1000 (3 points) precision */

## PQ KEMs algortithm
The PQ KEMs that are going to be used must be selected on the makefile_config.mk file in order to reserve the smaller necessary buffers. Behind a list of available KEMs until the date. 

### KYBER 512
- FEATURES += -DKYBER_LEVEL_1
### KYBER 768   
-  FEATURES += -DKYBER_LEVEL_3
### HQC 128 
- FEATURES += -DHQC_LEVEL_1
### BIKE 1 
- FEATURES += -BIKE_LEVEL_1


## PQ Signature algorithms
The PQ signature algorithms that are going to be used must be selected on the makefile_config.mk file in order to reserve the smaller necessary buffers. Behind a list of available signatures until the date.
### FALCON 512
- FEATURES += -DFALCON_LEVEL_1
### DILITHIUM 2
- FEATURES += -DDILITHIUM_LEVEL_1
### HAWK 512
- FEATURES += -DHAWK_LEVEL_1
### HAETAE 2
- FEATURES += -DHAETAE_LEVEL_2

## PQ credential types
### x5t
- By default type. A has of the x509 certificate is send it as crential
### s5chain
- A CBOR enconded verion of x509 certificate is send it as credential. This functionality must be selected at compile time by adding the following feature.
- FEATURES += -DUSE_X5CHAIN


## LINUX TEST 
The inititator and responder sources in this folder runs the test that we select it for comparing. The correct combination of KEMs and Signature algorithms as well as the credential type to be used must be selected at compile time in the makefile_config.mk file. 
The responder and initiator main function select the corresponding test vector for each combination that are setting with all the necessary information at test_vectors/edhoc_test_vectors_p256_v16.h file.
The test that we want to run and compare are:


### TEST_VECTOR_2 
- FEATURES += -DDH

### TEST_VECTOR_3 
- FEATURES += -DDH
- FEATURES += -DUSE_X5CHAIN

### TEST_VECTOR_7 
- FEATURES += -DKYBER_LEVEL_1
- FEATURES += -DFALCON_LEVEL_1
- CRYPTO_ENGINE += -DLIBOQS

### TEST_VECTOR_8 
- FEATURES += -DKYBER_LEVEL_1
- FEATURES += -DFALCON_LEVEL_1
- FEATURES += -DUSE_X5CHAIN
- CRYPTO_ENGINE += -DLIBOQS

### TEST_VECTOR_9 
- FEATURES += -DKYBER_LEVEL_3
- FEATURES += -DFALCON_LEVEL_1
- CRYPTO_ENGINE += -DLIBOQS

### TEST_VECTOR_10 
- FEATURES += -DKYBER_LEVEL_3
- FEATURES += -DFALCON_LEVEL_1
- FEATURES += -DUSE_X5CHAIN
- CRYPTO_ENGINE += -DLIBOQS

### TEST_VECTOR_11
- FEATURES += -DKYBER_LEVEL_1
- FEATURES += -DDILITHIUM_LEVEL_2
- CRYPTO_ENGINE += -DLIBOQS

### TEST_VECTOR_12 
- FEATURES += -DKYBER_LEVEL_1
- FEATURES += -DDILITHIUM_LEVEL_2
- FEATURES += -DUSE_X5CHAIN
- CRYPTO_ENGINE += -DLIBOQS

### TEST_VECTOR_13
- FEATURES += -DHQC_LEVEL_1
- FEATURES += -DFALCON_LEVEL_1
- CRYPTO_ENGINE += -DLIBOQS

### TEST_VECTOR_14
- FEATURES += -DBIKE_LEVEL_1
- FEATURES += -DFALCON_LEVEL_1
- CRYPTO_ENGINE += -DLIBOQS

### TEST_VECTOR_15
- FEATURES += -DBIKE_LEVEL_1
- FEATURES += -DDILITHIUM_LEVEL_2
- CRYPTO_ENGINE += -DLIBOQS

### TEST_VECTOR_16
- FEATURES += -DKYBER_LEVEL_1
- FEATURES += -DHAWK_LEVEL_1
- CRYPTO_ENGINE += -DLIBOQS
- CRYPTO_ENGINE += -DMUPQ 

### TEST_VECTOR_17
- FEATURES += -DKYBER_LEVEL_1
- FEATURES += -DHAETAE_LEVEL_2
- CRYPTO_ENGINE += -DLIBOQS
- CRYPTO_ENGINE += -DMUPQ 