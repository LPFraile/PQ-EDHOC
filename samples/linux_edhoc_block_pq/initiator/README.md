# PQ EDHOC Linux samples proposal 1: 
This folder contains
* initiator - PQ EDHOC initiator running on top of a CoAP client with Block Wise Transfer 

## Build and Run
Before running this example, you should have already run the responder in another terminal.
```
make clean
make -j
./build/iniator
```