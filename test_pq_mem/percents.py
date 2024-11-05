import sys
import os

def extract_totals_from_elf(file_path):
    """Extract total values from elf.txt."""
    totals = {"text": 0, "data": 0, "bss": 0, "dec": 0}

    with open(file_path, 'r') as file:
        lines = file.readlines()
        # The first line usually contains headers, so we skip it
        for line in lines[1:]:
            parts = line.strip().split()
            if len(parts) >= 6:  # Ensure there are enough parts
                totals["text"] = int(parts[0])
                totals["data"] = int(parts[1])
                totals["bss"] = int(parts[2])
                totals["dec"] = int(parts[3])

    return totals

def extract_totals_from_pqm4(file_path):
    """Extract total values from pqm4.txt."""
    totals = {"text": 0, "data": 0, "bss": 0, "dec": 0}

    with open(file_path, 'r') as file:
        lines = file.readlines()
        for line in lines:
            line = line.strip()
            if line.startswith("nontext:"):
                totals["text"] = int(line.split(":")[1].strip())
            elif line.startswith("nondata:"):
                totals["data"] = int(line.split(":")[1].strip())
            elif line.startswith("nonbss:"):
                totals["bss"] = int(line.split(":")[1].strip())
            elif line.startswith("nondec:"):
                totals["dec"] = int(line.split(":")[1].strip())
    
    return totals

def read_totals_from_libsize(file_path):
    """Read totals from libsize.txt."""
    totals = {"text": 0, "data": 0, "bss": 0, "dec": 0}

    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()
            if line.startswith("Total Text:"):
                totals["text"] = int(line.split(":")[1].strip())
            elif line.startswith("Total Data:"):
                totals["data"] = int(line.split(":")[1].strip())
            elif line.startswith("Total BSS:"):
                totals["bss"] = int(line.split(":")[1].strip())
            elif line.startswith("Total DEC:"):
                totals["dec"] = int(line.split(":")[1].strip())
    
    return totals

def calculate_percentage(totals_a, totals_b):
    """Calculate the percentage of totals_a relative to totals_b."""
    percentages = {}
    for key in totals_a.keys():
        if totals_b[key] > 0:  # Avoid division by zero
            percentages[key] = (totals_a[key] / totals_b[key]) * 100
        else:
            percentages[key] = 0  # If totals_b is 0, set percentage to 0
    return percentages

def main(repo_path):
    pqm4_file_path = os.path.join(repo_path, 'pqm4.txt')  # Adjusted file path
    elf_file_path = os.path.join(repo_path, 'elf.txt')    # Adjusted file path
    libsize_file_path = os.path.join(repo_path, 'libsize.txt')  # Adjusted file path

    pqm4_totals = extract_totals_from_pqm4(pqm4_file_path)
    elf_totals = extract_totals_from_elf(elf_file_path)
    libsize_totals = read_totals_from_libsize(libsize_file_path)

    pqm4_percentages = calculate_percentage(pqm4_totals, elf_totals)
    libsize_percentages = calculate_percentage(libsize_totals, elf_totals)

    print("Total values from pqm4.txt:")
    print(pqm4_totals)
    print("\nTotal values from elf.txt:")
    print(elf_totals)
    print("\nTotal values from libsize.txt:")
    print(libsize_totals)

    print("\nPercentages of pqm4 totals relative to elf totals:")
    for key, value in pqm4_percentages.items():
        print(f"{key.capitalize()} percentage: {value:.2f}%")

    print("\nPercentages of libsize totals relative to elf totals:")
    for key, value in libsize_percentages.items():
        print(f"{key.capitalize()} percentage: {value:.2f}%")

if __name__ == '__main__':
    # Ensure the repository path is provided as an argument
    if len(sys.argv) != 2:
        print("Usage: python3 percents.py <repository_path>")
        sys.exit(1)

    repo_path = sys.argv[1]
    main(repo_path)
  
