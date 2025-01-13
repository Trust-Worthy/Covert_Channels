import re
from collections import defaultdict

# Regular expressions to identify packet types
packet_patterns = {
    'ICMP6': r"ICMP6",
    'UDP': r"UDP",
    'QUIC': r"quic",
    'IP': r"IP",
    'IP6': r"IP6"
}

def parse_packet_file(file_path):
    packet_counts = defaultdict(int)
    total_packets = 0

    # Open the file
    with open(file_path, 'r') as file:
        for line in file:
            total_packets += 1
            # Check for packet types in the line
            for packet_type, pattern in packet_patterns.items():
                if re.search(pattern, line):
                    packet_counts[packet_type] += 1
                    break  # Stop after first match (since one packet is usually one type)

    # Print packet counts and percentages
    print(f"Total packets: {total_packets}\n")
    
    for packet_type in packet_patterns.keys():
        count = packet_counts[packet_type]
        percentage = (count / total_packets) * 100 if total_packets else 0
        print(f"{packet_type}: {count} packets ({percentage:.2f}%)")
    
    # Add total summary
    print(f"\nSummary:")
    print(f"Total ICMP6 packets: {packet_counts['ICMP6']}")
    print(f"Total UDP packets: {packet_counts['UDP']}")
    print(f"Total QUIC packets: {packet_counts['QUIC']}")
    print(f"Total IP packets: {packet_counts['IP']}")
    print(f"Total IP6 packets: {packet_counts['IP6']}")

if __name__ == "__main__":
    # Specify the path to your packet text file
    packet_file_path = 'captured_packets/capturecapture1.txt'
    parse_packet_file(packet_file_path)
