import re
from collections import defaultdict

# Function to parse each packet and extract relevant information
def parse_packet(packet):
    stats = defaultdict(int)
    
    # Regex for matching packet details
    timestamp_regex = r"^(\d+\.\d+)\s+"
    ip_version_regex = r"IP(\d)"
    icmp_type_regex = r"ICMP(\d+),\s([^,]+)"
    udp_regex = r"UDP,\slength\s(\d+)"
    packet_length_regex = r"length\s(\d+)"
    
    # Check if it's an IP packet (either IPv4 or IPv6)
    ip_match = re.search(ip_version_regex, packet)
    if ip_match:
        ip_version = ip_match.group(1)
        stats[f"IPv{ip_version}"] += 1
    
    # Check if it's ICMP and extract the ICMP type
    icmp_match = re.search(icmp_type_regex, packet)
    if icmp_match:
        icmp_type = icmp_match.group(2).strip().lower()
        stats[f"ICMP: {icmp_type}"] += 1
    
    # Check if it's a UDP packet and get the length
    udp_match = re.search(udp_regex, packet)
    if udp_match:
        udp_length = int(udp_match.group(1))
        stats["UDP packets"] += 1
        stats["Total UDP length"] += udp_length
    
    # Extract packet length
    length_match = re.search(packet_length_regex, packet)
    if length_match:
        packet_length = int(length_match.group(1))
        stats["Total packet length"] += packet_length
        stats["Total packets"] += 1
    
    return stats


# Main function to process the file and gather statistics
def process_packets(file_path):
    with open(file_path, 'r') as file:
        stats = defaultdict(int)
        
        packet_data = ""
        for line in file:
            # If we encounter a line that is a packet header (e.g., IP6 or IP), process the previous packet
            if line.startswith('1736800338'):  # Packet header line (timestamp)
                if packet_data:
                    # Parse the previous packet
                    packet_stats = parse_packet(packet_data)
                    for key, value in packet_stats.items():
                        stats[key] += value
                packet_data = line.strip()  # Start new packet
            else:
                packet_data += " " + line.strip()  # Continue appending packet data
        
        # Process the last packet after the file ends
        if packet_data:
            packet_stats = parse_packet(packet_data)
            for key, value in packet_stats.items():
                stats[key] += value
    
    return stats

# Function to print statistics in a readable format
def print_statistics(stats):
    print("Packet Statistics:")
    for key, value in stats.items():
        print(f"{key}: {value}")

if __name__ == "__main__":
    # Provide the path to your packet data file
    file_path = "captured_packets/capturecapture1.txt"  # Replace with your file path
    stats = process_packets(file_path)
    print_statistics(stats)
