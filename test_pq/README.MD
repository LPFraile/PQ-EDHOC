# Tests PQ-uEDHOC

This folder contains tests for PQ-uEDHOC, which can be executed on an embedded board (e.g., nrf51dk) using Zephyr OS for building. 

## CMake preprocessor definition
### Select the Test
- Run PQC Digital Signature Benchmark:
```
-DUSE_TEST_SIG=1
```
- Run PQC KEMs Benchmark:
```
-DUSE_TEST_KEM=1
```
- Run PQ-EDHOC Complete Test (Initiator and Responder communicating through a TX/RX buffer):
```
-DUSE_TEST_EDHOC=1
```
- Run PQ-EDHOC Initiator Alone:
```
-DUSE_TEST_INITIATOR=1
```
- Run PQ-EDHOC Responder Alone:
```
-DUSE_TEST_RESPONDER=1
```

### Select the Cipher Suit Under test
- Cipher suit 8: ML-KEM-512/FALCON1
```
-DUSE_SUIT_7=ON
```
- Cipher suit 9: ML-KEM-768/FALCON1 
```
-DUSE_SUIT_9=ON
```
- Cipher suit 10: HQC1/FALCON1
```
-DUSE_SUIT_10=ON
```
- Cipher suit 11: BIKE1/FALCON1 
```
-DUSE_SUIT_11=ON
```
- Cipher suit 12: ML-KEM-512/ML-DSA-44 
```
-DUSE_SUIT_12=ON
```
- Cipher suit 14: ML-KEM-512/HAWK1 
```
-DUSE_SUIT_14=ON
```
- Cipher suit 15: ML-KEM-512/HAETAE2 
```
-DUSE_SUIT_15=ON
```

### Select the Credential Type Under Test
- **x5t**  (Default) -> A has of the **X.509 certificate** is sent as credential.
```
-DUSE_X5T=1
```
- **x5chain** ->  A **CBOR enconded verion of x509 certificate** is sent as the credential:
```
-DUSE_X5CHAIN=1
```

### Select the Reports you Want to Get
- Measure time delay in cycles count with the High-Frequency clock (HFCLK) for the highest accuracy:
```
-DMEASURE_CLK=1
```
- Enable power measurement by triggering the necessary signals for oscilloscope measurements: 
```
-DPOWER_MEASUREMENTS=1   
```
Note: Do not use together with HFCLK, as enabling both will affect power consumption measurements. Instead, use:
```
-DMEASURE_LATENCY_PER_THREAD=1   
```
- Report Stack Usage
```
-DREPORT_STACK_USAGE=1
```
## Running Benchmark
### Run PQC Digital Signature Benchmark
```bash
cd test-pq/
source <path>/zephyr-env.sh 
rm -rf build/; 
west build -b nrf52840dk_nrf52840 -- -DUSE_TEST_SIG=1 -DUSE_X5T=1 -DUSE_SUIT_7=ON -DUSE_INTE_NUM=100 -DMEASURE_CLK=1 -DREPORT_STACK_USAGE=1 
west flash
```
### Run PQC KEMs Benchmark
```bash
cd test-pq/
source ~/zephyrproject/.venv/bin/activate
rm -rf build/; 
west build -b nrf52840dk_nrf52840 -- -DUSE_TEST_KEM=1 -DUSE_X5T=1 -DUSE_SUIT_7=ON -DUSE_INTE_NUM=100 -DMEASURE_CLK=1 -DREPORT_STACK_USAGE=1 
west flash
```
### Run PQC EDHOC Benchmark
```bash
cd test-pq/
source ~/zephyrproject/.venv/bin/activate
rm -rf build/; 
west build -b nrf52840dk_nrf52840 -- -DUSE_TEST_EDHOC=1 -DUSE_X5T=1 -DUSE_SUIT_7=ON -DUSE_INTE_NUM=100 -DMEASURE_CLK=1 -DREPORT_STACK_USAGE=1 
west flash
```