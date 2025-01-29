# Post Quantum EDHOC (PQ-EDHOC): 

## Description
This repository extends the **IETF Ephemeral Diffie-Hellman Over COSE (EDHOC)** protocol ([RFC9528](https://datatracker.ietf.org/doc/rfc9528/)) to support quantum-resistant cipher suites. It implements necessary architectural adjustments in the [uOSCORE-uEDHOC](https://github.com/eriptic/uoscore-uedhoc) library and integrates various Post-Quantum Cryptography (PQC) engines through the uOSCORE-uEDHOC cryptowrapper interface. The implementation supports **PQC Key Encapsulation Mechanisms (KEMs)** for key derivatiob and **PQC digital signatures** for authentication, from the National Institute of Standards and Technology (NIST) PQC standardization process, resulting in a complete **Post-Quantum (PQ)** version of the **EDHOC** protocol, referred to as **PQ-EDHOC**. 

**EDHOC** is a very compact and lightweight authenticated DH key exchange protocol for establishing a shared secret based on ephemeral keys. It provides identity protection, perfect forward secrecy, and mutual authentication based on out-of-band established credentials. The **uOSCORE-uEDHOC** library OS-independent implementation of EDHOC, and the post-quantum version follows the same design. The library on this repo can be compiled for **Linux base OSes**  as well as RTOS environments like **Zephyr OS**. 

<!--**EDHOC** is design to be transport-independent, thoug the RFC recommends using a reliable transport mechanism, such as CoAP (Constrained Application Protocol) in reliable mode. Since PQC algorithms often lead to larger data sizes, EDHOC messages tend to grow significantly.  To ensure functionality in real-world constrained networks, CoAP messages must be fragmented using the CoAP Block-Wise Transfer mechanism ([RFC7959](https://datatracker.ietf.org/doc/html/rfc7959)). 

To support this, the examples provided in this repository include the Tx/Rx EDHOC callback functions for handling message transmission and reception using CoAP with Block-Wise Transfer. The Linux example uses the libcoap library, while the Zephyr OS example utilizes the coap-client API from the Zephyr OS network subsystem.
-->

## Post-Quantum Cryptography (PQC) Algorithms

| PQC KEMs                  | Linux Support | Cortex-M4 Support |
|---------------------------|---------------|-------------------|
| **ML-KEM-512**            | ✔️             | ✔️                 |
| **HQC1**                  | ✔️             | ❌                |
| **BIKE1**                 | ✔️             | ❌                |

| PQC Digital Signatures    | Linux Support | Cortex-M4 Support |
|---------------------------|---------------|-------------------|
| **ML-DSA-44**             | ✔️             | ✔️                 |
| **FALCON1**               | ✔️             | ✔️                 |
| **HAWK1**                 | ✔️             | ✔️                 |
| **HAETAE2**               | ✔️             | ✔️                 |

### Suported Extra PQC Cipher Suits 

| Suit | Algorithms                                                                       |
| ---- | -------------------------------------------------------------------------------- |
| 8    | AES-CCM-16-64-128, SHA-256, 8, ML-KEM-512, FALCON1, AES-CCM-16-64-128, SHA-256   |
| 9    | AES-CCM-16-64-128, SHA-256, 8, ML-KEM-768, FALCON1, AES-CCM-16-64-128, SHA-256   |
| 10   | AES-CCM-16-64-128, SHA-256, 8, HQC1, FALCON1, AES-CCM-16-64-128, SHA-256         |
| 11   | AES-CCM-16-64-128, SHA-256, 8, BIKE1, FALCON1, AES-CCM-16-64-128, SHA-256        |
| 12   | AES-CCM-16-64-128, SHA-256, 8, ML-KEM-512, ML-DSA-44, AES-CCM-16-64-128, SHA-256 |
| 14   | AES-CCM-16-64-128, SHA-256, 8, ML-KEM-512, HAWK1, AES-CCM-16-64-128, SHA-256     |
| 15   | AES-CCM-16-64-128, SHA-256, 8, ML-KEM-512, HAETAE2, AES-CCM-16-64-128, SHA-256   |


## Cryptography Engines Integrated:
- [liboqs](https://github.com/open-quantum-safe/liboqs) (commit hash `d0353500`) and [mupq](https://github.com/mupq/mupq) for Linux based non-constrained devices. 
- [pqm4](https://github.com/mupq/pqm4) (commit hash `8d44b72`) and [PQClean](https://github.com/PQClean/PQClean) for Zephyr OS application on Cortex-M4 embedded systems.

## Dependencies on Other Software Components 
To compile the library on Linux, the **liboqs** library must first be built and linked to the project. Additionally, for examples that use the CoAP protocol with the Block-Wise Transfer mechanism, **libcoap** should also be built and linked to the project.

### [liboqs](https://github.com/open-quantum-safe/liboqs) 
An open source C library for quantum-safe cryptographic algorithms. This library need to be compile without openssl. Following the steps below:
```
 mkdir build
 cd build
 cmake -G Ninja .. -DOQS_USE_OPENSSL=OFF
 Ninja 
```
### [libcoap](https://github.com/obgm/libcoap)
C implementation of a lightweight application-protocol for devices that are constrained their resources such as computing power, RF range, memory, bandwidth, or network packet sizes. This protocol, CoAP, is standardized by the IETF as [RFC7252](https://datatracker.ietf.org/doc/html/rfc7252) and support Block-Wise transfer mechanism ([RFC7959](https://datatracker.ietf.org/doc/html/rfc7959)). 
```
 cmake -E remove_directory build
 cmake -E make_directory build
 cd build
 cmake .. -DENABLE_DTLS=OFF
 cmake --build .
 [sudo] cmake --build . -- install
```

## Configuring
To configure the examples at this project and correctly use the **PQ-uEDHOC** library, you must edit the configuration file [makefile_config.mk](makefile_config.mk)

### Transport Layer
Choose the transport layer: **TCP** or **UDP**. By default, **UDP** is selected. To use **TCP**, define the following macro:
```
FEATURES += -DUSE_TCP 
```
### CoAP Block-Wise Transfer 
For examples with Block-Wise Transfer, the block size must be chosen at compile time. The supported sizes are: **0 (reset)**, **32**, **64**, **128**, **256**, **512**, or **1024**. Configure it at compile time by defining the following macro:
```
FEATURES += -DUSE_COAP_BLOCK_SIZE=512 
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

## Linux Examples
For more details on each example, check the corresponding **README** file.

### PQ EDHOC over COAP

**Path:** `PQ-uEDHOC/samples/linux_pq_edhoc`
This folder contains two examples designed to run on a **Linux** host. See the [README](samples/linux_pq_edhoc/README.MD) for details.

- **Initiator:** PQ-EDHOC initiator running on top of a **CoAP client** without **Block-Wise Transfer**.

- **Responder:** PQ-EDHOC responder running on top of a **CoAP server** without **Block-Wise Transfer**.

These examples use the **cantcoap** library, which is the default CoAP library used in **uEDHOC** examples. However, **cantcoap** does not handle **CoAP packet loss** or **retransmissions**.

### PQ EDHOC over COAP with BLock Wise Transfer
**Path:** `PQ-uEDHOC/samples/linux_edhoc_block_pq`

This folder contains two examples designed to run on a **Linux** host. See the [README](samples/linux_pq_edhoc/README.MD) for details.

- **Initiator:** PQ-EDHOC initiator running on top of a **CoAP client** with **Block-Wise Transfer**.
- **Responder:** PQ-EDHOC responder running on top of a **CoAP server** with **Block-Wise Transfer**.


## Tested Platforms
This project has been successfully tested on the following platforms:

- **x86 computer** with **Ubuntu 24.04**
- **nRF52840-DK** board by Nordic Semiconductors with **Zephyr OS** (version:zephyr-v3.4.0-1-g099d9292556) 

## License



(the original README follows)

# uOSCORE / uEDHOC 

![GitHub CI](https://github.com/eriptic/uoscore-uedhoc/actions/workflows/ci.yml/badge.svg)


This repository contains C implementations  for constrained (and non-constrained) devices of the IETF protocols:

* [OSOCRE (RFC8613)](https://tools.ietf.org/html/rfc8613) and
* [EDHOC (draft-ietf-lake-edhoc-15 )](https://datatracker.ietf.org/doc/html/draft-ietf-lake-edhoc-15). 

Main features of uOSCORE and uEDHOC are their independence from the OS, cryptographic engine and in the case of uEDHOC transport protocol. Additionally,  uOSCORE and uEDHOC use only stack memory (no heap).

For more background and evaluation in terms of speed, RAM and flash requirements see our paper [The Cost of OSCORE and EDHOC for Constrained Devices](https://arxiv.org/pdf/2103.13832.pdf).

## How to Build and Link

* check the configurations in `makefile_config.mk` and adjust them if necessary
* run `make` 
* link the static library `build/libuoscore-uedhoc.a` in your project

## Test coverage
* [Test coverage report uOSCORE](https://eriptic.github.io/uoscore-uedhoc/src/oscore/index.html)
* [Test coverage report uEDHOC](https://eriptic.github.io/uoscore-uedhoc/src/edhoc/index.html)

## Benchmarks
* See [Benchmarks](benchmarks.md)

## Project (Folder) Structure

```
.
|---cddl_models/
|---externals/
|---inc/
|---samples/
|---scripts/
|---src/
|---test/
|---test_vectors/
```
* The folder `cddl_models` contains CDDL models for all CBOR structures.
* The folder `externals` contains the external libraries and tools as git submodules.
* The folder `inc` contains all header file.
* The folder `samples` contains some usage examples.
* The folder `scripts` contains scripts for generatinc C code from CDDL models and converting the json formatted EDHOC test vectors to a C header
* The folder `src` contains all source file.
* The folder `test` contains automated tests. 
* The folder `test_vectors` contains tests vectors. 

## API and Usage Model

#### uOSCORE

The API of uOSCORE consists of three functions: 
* `oscore_context_init()`,
*  `coap2oscore()` and 
*  `oscore2coap()`.

`coap2oscore()` and `oscore2coap()` convert CoAP to OSCORE packets and vice versa. `oscore_context_init()` initializes the OSCORE security context. 

First, `oscore_context_init()` function needs to be called on the client and server side, then `coap2oscore()` and `oscore2coap()`  are called just before sending or receiving packets over the network.

<img src="oscore_usage.svg" alt="drawing" width="600"/>


#### uEDHOC

The API of uEDHOC consists of four functions:
*  `ephemeral_dh_key_gen()`
* `edhoc_initiator_run()`,
* `edhoc_responder_run()`,
* `edhoc_exporter()`,

`ephemeral_dh_key_gen()` is used to generate fresh ephemeral DH keys before running the protocol. This function requires a random seed suable for cryptographic purposes. `edhoc_initiator_run()` and `edhoc_responder_run() ` has to be called on the initiator and responder side respectively. They return the External Authorization data `EAD_x`,  the derived shared secret `PRK_out`.   `PRK_out` is used as input for `edhoc_exporter()` to derive application specific keys, e.g., OSCORE master secret and OSCORE master salt.

The EDHOC protocol requires the exchange of three messages (and an optional message 4) which is independent of the underlying message transport protocol. For example [appendix-A.2 in the EDHOC specification](https://datatracker.ietf.org/doc/html/draft-ietf-lake-edhoc-15#appendix-A.2) describes how  EDHOC can be transferred over CoAP, however CoAP is not mandatory. In order to be independent of the transport protocol uEDHOC uses two callback functions which need to be implemented by the user for handling the sending and receiving of messages. These functions are:

```c
/**
 * @brief   The user should call inside this function its send function. 
 *
 * 
 * @param   sock a pointer used to identify the rx chanel, 
 *          e.g. a socket handler
 * @param   data data to be send
 */
enum err tx(void *sock, struct byte_array *data);

/**
 * @brief   The user should call inside this function its receive 
 *          function. The user should copy the received data in \p data.
 *          
 *          THE USER MUST MAKE SURE THAT HE/SHE IS NOT WRITING DATA OUTSIDE THE 
 *          RECEIVE BUFFER, I.E., THE LENGTH OF THE RECEIVED DATA IS SMALLER 
 *          THAN \p data->len. 
 * 
 *          After copying, the length of the received data should be written 
 *          in \p data->len.
 *
 * 
 * @param   sock a pointer used to identify the rx chanel, 
 *          e.g. a socket handler
 * @param   data the received message must be copied here
 */
enum err rx(void *sock, struct byte_array  *data);
```

Note that uEDHOC does not provide correlation of messages. Correlation may be handled on the transport layer completely or partially. In cases when the correlation cannot be handled by the transport protocol the edhoc message needs to be prepended with a connection identifier, that is used on the other side to determine to which session a given message belongs. In order to remain conform with the specification in the cases where the transport cannot handle correlation a connection identifier needs to be prepended in `tx()` function and removed in the `rx()` function.


## Supported Cipher Suites

##### uOSCORE

| Algorithms                  |
| --------------------------- |
| AES-CCM-16-64-128,  SHA-256 |

##### uEDHOC


| Suit | Algorithms                                                                 |
| ---- | -------------------------------------------------------------------------- |
| 0    | AES-CCM-16-64-128, SHA-256, 8, X25519, EdDSA, AES-CCM-16-64-128, SHA-256   |
| 1    | AES-CCM-16-128-128, SHA-256, 16, X25519, EdDSA, AES-CCM-16-64-128, SHA-256 |
| 2    | AES-CCM-16-64-128, SHA-256, 8, P-256, ES256, AES-CCM-16-64-128, SHA-256    |
| 3    | AES-CCM-16-128-128, SHA-256, 16, P-256, ES256, AES-CCM-16-64-128, SHA-256  |

## Using Different Cryptographic Libraries or Hardware Accelerators

The logic of uOSCORE and uEDHOC is independent form the cryptographic library, i.e., the cryptographic library can easily be exchanged by the user. For that the user needs to provide implementations for the functions specified in `crypto_wrapper.c`. 

## Preventing Nonce Reuse Attacks in OSCORE

AES keys should never be used more than once with a given nonce, see [RFC5084](https://datatracker.ietf.org/doc/html/rfc5084). In order to avoid this situation, the user has 2 options while creating context structure:
- setting `fresh_master_secret_salt = true`, when given context is new (freshly obtained e.g. with EDHOC)
- setting `fresh_master_secret_salt = false`, when the same context is used between reboots/reconnections. In this case, the user must enable Non-volatile Memory support (see `OSCORE_NVM_SUPPORT` in `makefile_config.mk`) and implement two functions that require access to NVM (see below).

Note that using NVM support is independent of the parameter above. Although it is required for using the same context multiple times, it will also be utilized (if enabled) to store context obtained with EDHOC, enabling the user to reuse it after the reboot. This behaviour is useful in situations where multiple sessions need to be stored on a device, while at the same time being able to start a completely new session with EDHOC. When such feature is not needed, `OSCORE_NVM_SUPPORT` can be disabled so only fresh sessions are acceptable.

   ```c
   /**
   * @brief When the same OSCORE master secret and salt are reused through
   *        several reboots of the device, e.g., no fresh shared secret is
   *        derived through EDHOC (or some other method) the Sender Sequence 
   *        Number MUST be stored periodically in NVM. 
   * @param nvm_key part of the context that is permitted to be used for identifying the right store slot in NVM.
   * @param	ssn SSN to be written in NVM.
   * @retval ok or error code if storing the SSN was not possible.
   */
   enum err nvm_write_ssn(const struct nvm_key_t *nvm_key, uint64_t ssn);

   /**
   * @brief When the same OSCORE master secret and salt are reused through
   *        several reboots of the device, e.g., no fresh shared secret is
   *        derived through EDHOC (or some other method) the Sender Sequence 
   *        Number MUST be restored from NVM at each reboot. 
   * @param nvm_key part of the context that is permitted to be used for identifying the right store slot in NVM.
   * @param	ssn SSN to be read out from NVM.
   * @retval ok or error code if the retrieving the SSN was not possible.
   */
   enum err nvm_read_ssn(const struct nvm_key_t *nvm_key, uint64_t *ssn);
   ```  

## Additional configuration options
The build configuration can be adjusted in the [makefile_config.mk](makefile_config.mk).