#!/bin/bash

# Check if the output directory is provided
if [ $# -ne 1 ]; then
    echo "Usage: $0 <output_directory>"
    exit 1
fi

OUTPUT_DIR=$1

# Check if the specified directory exists; create it if it doesn't
if [ ! -d "$OUTPUT_DIR" ]; then
    mkdir -p "$OUTPUT_DIR"
fi

# Run the size commands without opening new terminal windows
arm-zephyr-eabi-size build/zephyr/zephyr.elf > ${OUTPUT_DIR}/elf.txt
arm-zephyr-eabi-size build/app/libapp.a > ${OUTPUT_DIR}/app.txt
arm-zephyr-eabi-size build/uoscore_uedhoc/libuoscore-uedhoc.a > ${OUTPUT_DIR}/lib.txt

# Run the Python scripts
python3 app_percents_excludes.py ${OUTPUT_DIR}/app.txt > ${OUTPUT_DIR}/pqm4.txt
#python3 app_percents.py ${OUTPUT_DIR}/app.txt > ${OUTPUT_DIR}/pqm4.txt
python3 lib_code_size.py ${OUTPUT_DIR}/lib.txt > ${OUTPUT_DIR}/libsize.txt
python3 percents.py ${OUTPUT_DIR} > ${OUTPUT_DIR}/results.txt
