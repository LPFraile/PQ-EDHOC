import re
import argparse

# Define the keywords to filter filenames
keywords = ["pqm4", "kem", "sign", "verify"]

# Function to check if the filename contains any of the keywords
def contains_keywords(filename, keywords):
    return any(keyword in filename for keyword in keywords)

# Main function to process the file
def process_file(file_path):
    # Initialize sums for text, data, bss, and dec columns for matching files
    text_sum_matching = 0
    data_sum_matching = 0
    bss_sum_matching = 0
    dec_sum_matching = 0

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

            # If the filename contains any of the keywords, add to the matching sums
            if contains_keywords(filename, keywords):
                text_sum_matching += text
                data_sum_matching += data
                bss_sum_matching += bss
                dec_sum_matching += dec

    # Calculate percentages of the total for matching files
    if text_total > 0:
        text_percent = (text_sum_matching / text_total) * 100
    else:
        text_percent = 0

    if data_total > 0:
        data_percent = (data_sum_matching / data_total) * 100
    else:
        data_percent = 0

    if bss_total > 0:
        bss_percent = (bss_sum_matching / bss_total) * 100
    else:
        bss_percent = 0

    if dec_total > 0:
        dec_percent = (dec_sum_matching / dec_total) * 100
    else:
        dec_percent = 0

    # Print the results for matching files
    print(f"Matching Files:")
    print(f"Total text: {text_sum_matching}")
    print(f"Total data: {data_sum_matching}")
    print(f"Total bss: {bss_sum_matching}")
    print(f"Total dec: {dec_sum_matching}")

    # Print the total sums for all files
    print(f"\nAll Files:")
    print(f"Total text: {text_total}")
    print(f"Total data: {data_total}")
    print(f"Total bss: {bss_total}")
    print(f"Total dec: {dec_total}")

    # Print the percentages
    print(f"\nPercentage of totals from matching files:")
    print(f"Text: {text_percent:.2f}%")
    print(f"Data: {data_percent:.2f}%")
    print(f"BSS: {bss_percent:.2f}%")
    print(f"DEC: {dec_percent:.2f}%")

# Entry point for the script
if __name__ == '__main__':
    # Set up argument parsing
    parser = argparse.ArgumentParser(description='Process a text file and sum values from specific columns.')
    parser.add_argument('file', type=str, help='Path to the text file')

    # Parse the arguments
    args = parser.parse_args()

    # Call the processing function with the input file
    process_file(args.file)


