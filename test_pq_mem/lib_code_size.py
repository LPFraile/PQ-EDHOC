import sys

def measure_memory(input_file):
    total_text = 0
    total_data = 0
    total_bss = 0
    total_dec = 0
    total_hex = 0

    with open(input_file, 'r') as file:
        for line in file:
            # Ignore header and non-numeric lines
            if line.lstrip().startswith("text") or line.strip() == "":
                continue  # Skip header line and empty lines

            parts = line.split()
            if len(parts) >= 6:  # Ensure there are enough columns
                try:
                    # Convert the numeric parts to integers
                    text = int(parts[0])
                    data = int(parts[1])
                    bss = int(parts[2])
                    dec = int(parts[3])
                    hex_val = int(parts[4], 16)  # Convert hex string to integer

                    # Accumulate totals
                    total_text += text
                    total_data += data
                    total_bss += bss
                    total_dec += dec
                    total_hex += hex_val
                except ValueError as e:
                    print(f"Error parsing line: '{line.strip()}': {e}")

    # Print the results
    print(f"Total Text: {total_text}")
    print(f"Total Data: {total_data}")
    print(f"Total BSS: {total_bss}")
    print(f"Total DEC: {total_dec}")
    print(f"Total HEX: {hex(total_hex)}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python lib_code_size.py <input_file.txt>")
        sys.exit(1)

    input_file = sys.argv[1]
    measure_memory(input_file)

