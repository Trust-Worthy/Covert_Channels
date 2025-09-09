from pathlib import Path
import re

def clean_packets()-> None:

    available_files = print_clean_packets_options()

    ### TO-DO ### 
    # allow user to choose what files to clean

    output_directory = Path("../captures/cleaned_captures")

    for file in available_files.values():

        clean_file(file, output_dir=output_directory)

def clean_file(file_path: str, output_dir: str):
    protocol_set = {b"UDP", b"ICMP", b"ICMP6", b"TCP", b"TLS", b"IP", b"ARP", b"ETHERNET"}
    packet_start_pattern = re.compile(r"^\d{2}:\d{2}:\d{2}\.\d{6} .+")
    
    with open(file_path, "r") as uncleaned_file:
        cleaned_data: list[bytes] = []  # Data will be stored as bytes
        packet_metadata: list[bytes] = []  # Metadata will be stored as bytes
        current_packet_data: list[bytes] = []  # Store data for the current packet

        for line in uncleaned_file:
            # Check for the start of a new packet based on timestamp pattern
            if packet_start_pattern.match(line):
                # If a packet was being collected, save it
                if current_packet_data:
                    # Combine metadata and packet data into one byte sequence for each packet
                    cleaned_data.append(b"\n".join(packet_metadata + current_packet_data))
                
                # Clear previous packet data and metadata for the next packet
                current_packet_data = []
                packet_metadata = []
                
                # Capture the timestamp line as metadata
                packet_metadata.append(line.strip().encode())  # Store metadata as bytes
            else:
                # Match lines containing protocol info (e.g., "UDP", "ICMP6")
                for protocol in protocol_set:
                    if protocol in line.encode():  # Convert line to bytes for matching
                        packet_metadata.append(line.strip().encode())  # Store metadata as bytes

                # Skip the lines containing hexadecimal data offsets (e.g., "0x0000:")
                if line.startswith("0x"):
                    # Skip the offset and extract just the hex data (remove the "0x0000:" part)
                    hex_data = line.split(":")[1].strip()  # Extract hex data
                    byte_data = bytes.fromhex(hex_data)  # Convert hex data to bytes
                    current_packet_data.append(byte_data)  # Add byte data to current packet

                # Optionally, keep the raw byte data if it's not part of the "0x" offset
                elif len(line.strip()) == 47 and not line.startswith("0x"):  # Check for raw byte-like lines
                    byte_data = bytes.fromhex(line.strip())  # Convert the line to bytes
                    current_packet_data.append(byte_data)  # Add byte data to current packet

        # If there was a packet being collected at the end of the file, save it
        if current_packet_data:
            cleaned_data.append(b"\n".join(packet_metadata + current_packet_data))

        # Write the cleaned data to a new file in the cleaned_captures directory
        cleaned_filename = os.path.join(output_dir, "cleaned" + os.path.basename(file_path))

        with open(cleaned_filename, "wb") as cleaned_file:  # Open in binary write mode
            cleaned_file.write(b"\n".join(cleaned_data))  # Write bytes to the file
            print(f"Cleaned file saved as {cleaned_filename}")

# Example usage
# clean_file("path/to/uncleaned_file.txt", "path/to/output_dir")