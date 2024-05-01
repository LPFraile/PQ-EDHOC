# PQ EDHOC initiator
## Abstract
PQ EDHOC Initiator example running on Linux. Runs edhoc method 0 and every of the new PQ ciphersuits add it on uedhoc library. 

## Set Up 
- Select the PQ KEMs and PQ Signature algorithm to be used on the makefile_config.mk file
- Select on the initiator/makefile big enough maxline for the selected KEMs and Signature
```
CXXFLAGS += -DMAXLINE=6000 
CFLAGS += -DMAXLINE=6000
```
- Select on the iniatore/main.cpp file the PQ proposal 1
```
#define PQ_PROPOSAL_1
```
- Select on the iniator/main.cpp file the *TEST_VEC_NUM* to be used from the tested list and in the test vector the corresponding cipher suit
 ```
 uint8_t TEST_VEC_NUM = 8;
 ```

## Build and Run
Once has been already run a reponder in another terminal
```
make clean
make -j
./build/iniator
```