# Function to generate the mask for a range of values
def generate_mask(range_start, range_end):
    """
    Generates a wildcard mask between two decimal numbers.
   
    :param range_start: Starting number of the range.
    :param range_end: Ending number of the range.
    :return: The wildcard mask in binary format as an integer.
    """
    # XOR the start and end, which will show the bits that are different
    range_xor = range_start ^ range_end
   
    # Calculate the number of bits needed for the start and end
    max_bit_length = max(range_start.bit_length(), range_end.bit_length())

    # Create the mask: find the first differing bit position and create a mask
    significant_bits = range_xor.bit_length()
   
    # All bits up to the first differing bit will be fixed (set to 1), the rest will be wildcards (set to 0)
    if significant_bits == 0:
        mask = 0xFFFFFFFFF  # All bits are identical
    else:
        mask = ~((1 << significant_bits) - 1) & 0xFFFFFFFFF
   
    return mask

# Function to convert a range into wildcard match entries
def convert_range_to_wildcard(start, end):
    """
    Converts a given decimal range into wildcard (ternary) match entries.

    :param start: Starting integer of the range.
    :param end: Ending integer of the range.
    :return: A list of wildcard match entries in decimal and their corresponding mask.
    """
    wildcard_entries = []
   
    while start <= end:
        # Find the largest power of 2 that fits within the remaining range
        max_size = 1
        while (max_size << 1) <= start:
            max_size <<= 1

        # Adjust block size to ensure it does not exceed the end of the range
        while start + max_size - 1 > end:
            max_size >>= 1

        # Calculate the start and end for the current block in decimals
        range_start = start
        range_end = start + max_size - 1

        # Generate the wildcard mask
        mask = generate_mask(range_start, range_end)

        # Append the wildcard match entry (range_start, mask) to the result
        wildcard_entries.append((range_start, mask))

        # Move to the next part of the range
        start += max_size

    return wildcard_entries

# Example usage: Convert a range into wildcard match entries
def main(start, end):
    wildcard_entries = convert_range_to_wildcard(start, end)

    print("Generated Wildcard Entries (in decimal and hex mask):")
    for entry, mask in wildcard_entries:
        print(f"({hex(entry)}, {hex(mask)})")

# Call the function with an example range
if __name__ == "__main__":
    start_range = int(input("Enter the start of the range: "))
    end_range = int(input("Enter the end of the range: "))
    main(start_range, end_range)
