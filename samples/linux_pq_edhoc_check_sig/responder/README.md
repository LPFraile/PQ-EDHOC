# PQ EDHOC responder
## Abstract
PQ EDHOC Responder example running on Linux. Runs edhoc method 0 and every of the new PQ ciphersuits add it on uedhoc library. 

## Set Up 
- The correct setup must be setting on the makefile_config.mk file with one of the following combination. Botice that the same combination of kems signatures and credential types must be settinh also for the initiator.
### TEST_VECTOR_2 
- FEATURES += -DDH

### TEST_VECTOR_3 
- FEATURES += -DDH
- FEATURES += -DUSE_X5CHAIN

### TEST_VECTOR_7 
- FEATURES += -DKYBER_LEVEL_1
- FEATURES += -DFALCON_LEVEL_1

### TEST_VECTOR_8 
- FEATURES += -DKYBER_LEVEL_1
- FEATURES += -DFALCON_LEVEL_1
- FEATURES += -DUSE_X5CHAIN

### TEST_VECTOR_9 
- FEATURES += -DKYBER_LEVEL_3
- FEATURES += -DFALCON_LEVEL_1

### TEST_VECTOR_10 
- FEATURES += -DKYBER_LEVEL_3
- FEATURES += -DFALCON_LEVEL_1
- FEATURES += -DUSE_X5CHAIN

### TEST_VECTOR_11
- FEATURES += -DKYBER_LEVEL_1
- FEATURES += -DDILITHIUM_LEVEL_2

### TEST_VECTOR_12 
- FEATURES += -DKYBER_LEVEL_1
- FEATURES += -DDILITHIUM_LEVEL_2
- FEATURES += -DUSE_X5CHAIN

### TEST_VECTOR_13
- FEATURES += -DHQC_LEVEL_1
- FEATURES += -DFALCON_LEVEL_1

### TEST_VECTOR_14
- FEATURES += -DBIKE_LEVEL_1
- FEATURES += -DFALCON_LEVEL_1

### TEST_VECTOR_15
- FEATURES += -DBIKE_LEVEL_1
- FEATURES += -DDILITHIUM_LEVEL_2

## Build and Run
```
make clean
make -j
./build/responder
```
