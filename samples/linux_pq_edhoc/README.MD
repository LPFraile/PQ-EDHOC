# PQ EDHOC Linux samples proposal 1: 

This example implements the first PQ proposal for EDHOC, utilizing KEMs for session key derivation and PQ signatures for authentication. It employs method 0 and PQ cipher suites.

## Folder Overview
This folder contains two sample applications intended to be executed on a Linux host:
-  initiator - PQ EDHOC initiator running on top of a CoAP client without Block Wise Transfer
-  responder - PQ EDHOC responder running on top of a CoAP server without Block Wise Transfer

The repository includes submodules. Clone it using the `--recurse-submodules` option:
## Dependencies 
[liboqs](https://github.com/open-quantum-safe/liboqs) - An open source C library for quantum-safe cryptographic algorithms. This library need to be compile without openssl. Following the steps below:
```
 mkdir build
 cd build
 cmake -G Ninja .. -DOQS_USE_OPENSSL=OFF
 Ninja 
```

## Configuring
To configure the examples at this project and correctly use the **PQ-uEDHOC** library, you must edit the configuration file [makefile_config.mk](makefile_config.mk)

### Transport Layer
Choose the transport layer: **TCP** or **UDP**. By default, **UDP** is selected. To use **TCP**, define the following macro:
```
FEATURES += -DUSE_TCP 
```

### PQ KEMs algortithms
The **PQ KEMs** must be selected in order to allocate the smaller necessary buffer sizes. Below is a list of supported KEMs:

- ML-KEM-512
```
FEATURES += -DKYBER_LEVEL_1
```
- ML-KEM-768   
```
FEATURES += -DKYBER_LEVEL_3
```
- HQC1 
```
FEATURES += -DHQC_LEVEL_1
```
- BIKE1 
```
FEATURES += -BIKE_LEVEL_1
```

### PQC Digital Signature algorithms
The **PQ Digital Signature** schemes  must be selected to optimize memory allocation. Below is a list of supported signatures:

- FALCON 512
```
FEATURES += -DFALCON_LEVEL_1
```
- DILITHIUM 2
```
FEATURES += -DDILITHIUM_LEVEL_1
```
- HAWK 512
```
FEATURES += -DHAWK_LEVEL_1
```
- HAETAE 2
```
FEATURES += -DHAETAE_LEVEL_2
```

### PQ Credential types
The credential type must be selected.
- **x5t**  (Default) -> A has of the **X.509 certificate** is sent as credential.
- **x5chain** ->  A **CBOR enconded verion of x509 certificate** is sent as the credential. Enable this feature with:
```
FEATURES += -DUSE_X5CHAIN
```

## LINUX TEST 
The initiator and responder execute predefined test vectors for comparison. Select the appropriate combination of KEMs, signature algorithms, and credential types at compile time in Makefile_config.mk.

Test vectors are defined in `test_vectors/edhoc_test_vectors_p256_v16.h`.

### TEST_VECTOR_2 (Cipher suit 2 with X5T credentials)
```
FEATURES += -DDH
```
### TEST_VECTOR_3 (Cipher suit 2 with X5Chain credentials)
```
FEATURES += -DDH
FEATURES += -DUSE_X5CHAIN
```
### TEST_VECTOR_7 (Cipher suit 8 with X5T credentials)
```
FEATURES += -DKYBER_LEVEL_1
FEATURES += -DFALCON_LEVEL_1
CRYPTO_ENGINE += -DLIBOQS
```
### TEST_VECTOR_8 (Cipher suit 8 with X5Chain credentials)
```
FEATURES += -DKYBER_LEVEL_1
FEATURES += -DFALCON_LEVEL_1
FEATURES += -DUSE_X5CHAIN
CRYPTO_ENGINE += -DLIBOQS(Cipher suit 2 with X5Chain credentials)
CRYPTO_ENGINE += -DLIBOQS
```

### TEST_VECTOR_10 (Cipher suit 9 with X5Chain credentials)
```
FEATURES += -DKYBER_LEVEL_3
FEATURES += -DFALCON_LEVEL_1
FEATURES += -DUSE_X5CHAIN
CRYPTO_ENGINE += -DLIBOQS
```

### TEST_VECTOR_11 (Cipher suit 12 with X5T credentials)
```
FEATURES += -DKYBER_LEVEL_1
FEATURES += -DDILITHIUM_LEVEL_2
CRYPTO_ENGINE += -DLIBOQS
```

### TEST_VECTOR_12 (Cipher suit 12 with X5Chain credentials)
```
FEATURES += -DKYBER_LEVEL_1
FEATURES += -DDILITHIUM_LEVEL_2
FEATURES += -DUSE_X5CHAIN
CRYPTO_ENGINE += -DLIBOQS
```

### TEST_VECTOR_13 (Cipher suit 9 with X5T credentials)
```
FEATURES += -DHQC_LEVEL_1
FEATURES += -DFALCON_LEVEL_1
CRYPTO_ENGINE += -DLIBOQS
```

### TEST_VECTOR_14 (Cipher suit 10 with X5T credentials)
```
FEATURES += -DBIKE_LEVEL_1
FEATURES += -DFALCON_LEVEL_1
CRYPTO_ENGINE += -DLIBOQS
```

### TEST_VECTOR_15 
```
FEATURES += -DBIKE_LEVEL_1
FEATURES += -DDILITHIUM_LEVEL_2
CRYPTO_ENGINE += -DLIBOQS
```

### TEST_VECTOR_16 (Cipher suit 14 with X5T credentials)
```
FEATURES += -DKYBER_LEVEL_1
FEATURES += -DHAWK_LEVEL_1
CRYPTO_ENGINE += -DLIBOQS
CRYPTO_ENGINE += -DMUPQ 
```

### TEST_VECTOR_17 (Cipher suit 15 with X5T credentials)
```
FEATURES += -DKYBER_LEVEL_1
FEATURES += -DHAETAE_LEVEL_2
CRYPTO_ENGINE += -DLIBOQS
CRYPTO_ENGINE += -DMUPQ 
```
