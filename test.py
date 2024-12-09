def clean_and_extract_http_payload(input_file, cleaned_file):
    """Remove HTTP headers and extract the binary payload."""
    with open(input_file, "rb") as f:
        raw_data = f.read()

    # Convert the raw data to a string for header processing
    raw_text = raw_data.decode("utf-8", errors="ignore")

    # Locate the end of HTTP headers (double newline indicates headers end)
    headers_end_index = raw_text.find("\r\n\r\n")
    if headers_end_index == -1:
        raise ValueError("Could not locate the end of HTTP headers.")

    # Extract the payload (binary data starts after headers + 4 characters for \r\n\r\n)
    binary_payload = raw_data[headers_end_index + 4:]

    # Save the cleaned binary payload
    with open(cleaned_file, "wb") as f:
        f.write(binary_payload)

    print(f"Cleaned binary payload saved to {cleaned_file}")

# Input and output file paths
input_file = "raw_data.bin"  # Replace with your input file containing HTTP headers
cleaned_file = "cleaned_image.jpg"

try:
    # Step 1: Clean the raw data by removing HTTP headers
    clean_and_extract_http_payload(input_file, cleaned_file)

    print(f"Image extraction complete. File saved as {cleaned_file}")
except Exception as e:
    print(f"An error occurred: {e}")
