import csv
import sys

def read_file_column(file_path, column_name):
    """Read the specified column from a CSV file and return a set of values."""
    with open(file_path, 'r') as file:
        reader = csv.DictReader(file)
        return {row[column_name] for row in reader if column_name in row}

def compare_file_columns(file1, file2, column_name):
    """Compare two files and return the common values in the specified column."""
    file1_values = read_file_column(file1, column_name)
    file2_values = read_file_column(file2, column_name)

    # Find common values in both sets
    common_values = file1_values.intersection(file2_values)
    return list(common_values)

def main(file1_path, file2_path):
    column_name = "file"  # Column to compare
    common_files = compare_file_columns(file1_path, file2_path, column_name)

    print("Common files:")
    print(common_files)

if __name__ == '__main__':
    # Ensure two file paths are provided
    if len(sys.argv) != 3:
        print("Usage: python3 compare_file_columns.py <file1_path> <file2_path>")
        sys.exit(1)

    file1_path = sys.argv[1]
    file2_path = sys.argv[2]

    main(file1_path, file2_path)
