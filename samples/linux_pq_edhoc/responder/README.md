# PQ EDHOC responder
## Abstract
PQ EDHOC Responder example running on Linux. Runs edhoc method 0 and every of the new PQ ciphersuits add it on uedhoc library. 

## Set Up 
- Select the PQ KEMs and PQ Signature algorithm to be used on the makefile_config.mk file
- Select on the initiator/makefile big enough maxline for the selected KEMs and Signature
```
CXXFLAGS += -DMAXLINE=6000 
CFLAGS += -DMAXLINE=6000
```
- Select on the responder/main.cpp file the *TEST_VEC_NUM* to be used from the tested list
 ```
 uint8_t TEST_VEC_NUM = 8;
 ```

## Build and Run
```
make clean
make -j
./build/responder
```
