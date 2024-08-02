# PQ EDHOC Linux samples proposal 1: 

This example runs the first PQ proposal for EDHOC that use KEMs for session key derivations and PQ signature for authentication. It use method 0 and PQ ciphersuits 

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
At compile time you need to chose what transport layer to use TCP or UDP. By default UDP is selected. To use TCP the following macro must be definded in the [makefile_config.mk](makefile_config.mk) file.
- FEATURES += -DUSE_TCP 

## COAP BLOCK WISE TRANSFER CONFIGURATION
The coap client and server are setting to works with block wise transfer. The block size support must be chosed at compile time.  Can be 0(reset), or must be  32, 64, 128, 256, 512 or 1024. It is configure at compilation time by define the folowing macro in [makefile_config.mk](makefile_config.mk).
- FEATURES += -DUSE_COAP_BLOCK_SIZE=512 


## PQ KEMs algortithm
The PQ KEMs that are going to be used must be selected on the [makefile_config.mk](makefile_config.mk) file in order to reserve the smaller necessary buffers. Behind a list of available KEMs until the date. 

### KYBER 512
- FEATURES += -DKYBER_LEVEL_1
### KYBER 768   
-  FEATURES += -DKYBER_LEVEL_3
### HQC 128 
- FEATURES += -DHQC_LEVEL_1
### BIKE 1 
- FEATURES += -BIKE_LEVEL_1


## PQ Signature algorithms
The PQ signature algorithms that are going to be used must be selected on the [makefile_config.mk](makefile_config.mk) file in order to reserve the smaller necessary buffers. Behind a list of available signatures until the date.
### FALCON 512
- FEATURES += -DFALCON_LEVEL_1
### DILITHIUM 2
- FEATURES += -DDILITHIUM_LEVEL_1

## PQ credential types
The credential type must be selected on [makefile_config.mk](makefile_config.mk)
### x5t
- By default type. A has of the x509 certificate is send it as crential
### s5chain
- A CBOR enconded verion of x509 certificate is send it as credential. This functionality must be selected at compile time by adding the following feature.
- FEATURES += -DUSE_X5CHAIN


## LINUX EXAMPLES
* To more information of every example check on the corresponding README

### PQ EDHOC over COAP
- PQ-uEDHOC/samples/linux_pq_edhoc
This folder contains two samples intended to be executed on a Linux host ([README](samples/linux_pq_edhoc/README.MD))

* initiator - PQ EDHOC initiator running on top of a CoAP client without Block Wise Transfer
* responder - PQ EDHOC responder running on top of a CoAP server without Block Wise Transfer

The specific sample use cantcoap library, the by default coap that edhoc examples use in their tests. This library does not provide manage of coap packet losts and retrasmisions 

### PQ EDHOC over COAP with BLock Wise Transfer
- PQ-uEDHOC/samples/linux_edhoc_block_pq

This folder contains two samples intended to be executed on a Linux host ([README](samples/linux_pq_edhoc/README.MD))

* initiator - PQ EDHOC initiator running on top of a CoAP client with Block Wise Transfer
* responder - PQ EDHOC responder running on top of a CoAP server with Block Wise Transfer
