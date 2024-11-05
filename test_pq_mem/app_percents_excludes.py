import re
import argparse

# Define the keywords to filter out filenames (files to exclude)
keywords_to_exclude = ["main", "cbor", "utils", "_sha512.c.obj", "c25519.c.obj","ed25519", "edsign","f25519","fprime", "compact_ed25519", "compact_wipe","compact_x25519","aes_decrypt.c", "aes_encrypt","cbc_mode","cmac_mode","ctr_mode","ctr_prng","ecc.c","ecc_dh","ecc_dsa","ecc_platform","hmac", "tc_sha256"]

# Function to check if the filename contains any of the keywords to exclude
def contains_keywords(filename, keywords):
    return any(keyword in filename for keyword in keywords)

# Main function to process the file
def process_file(file_path):
    # Initialize sums for text, data, bss, and dec columns for non-matching files
    text_sum_non_matching = 0
    data_sum_non_matching = 0
    bss_sum_non_matching = 0
    dec_sum_non_matching = 0

    # Initialize total sums for all files
    text_total = 0
    data_total = 0
    bss_total = 0
    dec_total = 0

    # Open and read the text file
    with open(file_path, 'r') as file:
        # Skip the header line
        next(file)

        # Process each line in the file
        for line in file:
            # Split line into columns (assuming columns are separated by any whitespace)
            columns = re.split(r'\s+', line.strip())

            # Extract the values from the appropriate columns
            text = int(columns[0])
            data = int(columns[1])
            bss = int(columns[2])
            dec = int(columns[3])
            filename = columns[5]  # Filename is in the last column

            # Add to the total sums
            text_total += text
            data_total += data
            bss_total += bss
            dec_total += dec

            # If the filename does not contain any of the keywords, add to the non-matching sums
            if not contains_keywords(filename, keywords_to_exclude):
                text_sum_non_matching += text
                data_sum_non_matching += data
                bss_sum_non_matching += bss
                dec_sum_non_matching += dec

    # Calculate percentages of the total for non-matching files
    # These percentages will be based on the total values of all included files
    if text_total > 0:
        text_percent = (text_sum_non_matching / text_total) * 100
    else:
        text_percent = 0

    if data_total > 0:
        data_percent = (data_sum_non_matching / data_total) * 100
    else:
        data_percent = 0

    if bss_total > 0:
        bss_percent = (bss_sum_non_matching / bss_total) * 100
    else:
        bss_percent = 0

    if dec_total > 0:
        dec_percent = (dec_sum_non_matching / dec_total) * 100
    else:
        dec_percent = 0

    # Print the results for non-matching files
    print(f"Non-Matching Files (files excluding '{', '.join(keywords_to_exclude)}'):")
    print(f"nontext: {text_sum_non_matching}")
    print(f"nondata: {data_sum_non_matching}")
    print(f"nonbss: {bss_sum_non_matching}")
    print(f"nondec: {dec_sum_non_matching}")

    # Print the total sums for all files
    print(f"\nAll Files:")
    print(f"text: {text_total}")
    print(f"data: {data_total}")
    print(f"bss: {bss_total}")
    print(f"dec: {dec_total}")

    # Print the percentages
    print(f"\nPercentage of totals from non-matching files:")
    print(f"text: {text_percent:.2f}%")
    print(f"data: {data_percent:.2f}%")
    print(f"bss: {bss_percent:.2f}%")
    print(f"dec: {dec_percent:.2f}%")

# Entry point for the script
if __name__ == '__main__':
    # Set up argument parsing
    parser = argparse.ArgumentParser(description='Process a text file and sum values from specific columns.')
    parser.add_argument('file', type=str, help='Path to the text file')

    # Parse the arguments
    args = parser.parse_args()

    # Call the processing function with the input file
    process_file(args.file)

