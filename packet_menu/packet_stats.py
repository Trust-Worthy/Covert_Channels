import re
from collections import defaultdict

def parse_packet(packet_data):
    """
    Parses packet data to extract type and length based on different formats.
    """
    packet_info = {}
    
    # Format 1: UDP packet with 'UDP, length 40'
    udp_pattern = re.compile(r'\s+(\S+)\s+[\d\.]+(?:\.\d+)?\s+>\s+[\d\.]+(?:\.\d+)?\s*:\s*(\S+),\s*length\s*(\d+)')
    dns_pattern = re.compile(r'\s+(\S+)\s+[\d\.]+(?:\.\d+)?\s+>\s+[\d\.]+(?:\.\d+)?\s*:\s*\d+\+(\S+)\s*\?(\S+)\s*\.\s*\((\d+)\)')
    tcp_pattern = re.compile(r'\s+(\S+)\s+[\d\.]+(?:\.\d+)?\s+>\s+[\d\.]+(?:\.\d+)?\s*:\s*\(.*?length\s*(\d+)\)')

    # Match UDP format
    udp_match = udp_pattern.match(packet_data)
    if udp_match:
        packet_info['type'] = 'UDP'
        packet_info['length'] = int(udp_match.group(3))
        return packet_info

    # Match DNS query format
    dns_match = dns_pattern.match(packet_data)
    if dns_match:
        packet_info['type'] = 'DNS'
        packet_info['length'] = int(dns_match.group(4))
        return packet_info

    # Match TCP format
    tcp_match = tcp_pattern.match(packet_data)
    if tcp_match:
        packet_info['type'] = 'TCP'
        packet_info['length'] = int(tcp_match.group(2))
        return packet_info

    # If no match found, return None
    return None


def analyze_packets(file_path):
    """
    Analyzes packet statistics from the given file, considering multiple packet formats.
    """
    total_packets = 0
    packet_types = defaultdict(int)
    total_length = 0

    with open(file_path, 'r') as f:
        packet_data = ""
        for line in f:
            line = line.strip()

            # Detect if the line starts a new packet (based on timestamp)
            if line and re.match(r'^\d{4}-\d{2}-\d{2}', line):  # Matches timestamp-based line
                if packet_data:
                    packet_info = parse_packet(packet_data)
                    if packet_info:
                        total_packets += 1
                        packet_types[packet_info['type']] += 1
                        total_length += packet_info['length']
                packet_data = line
            else:
                # Continue accumulating hex dump lines or continuation lines
                packet_data += " " + line

        # Process the last packet in the file
        if packet_data:
            packet_info = parse_packet(packet_data)
            if packet_info:
                total_packets += 1
                packet_types[packet_info['type']] += 1
                total_length += packet_info['length']

    # Compute statistics
    packet_type_percentages = {
        packet_type: (count / total_packets) * 100
        for packet_type, count in packet_types.items()
    }

    average_packet_size = total_length / total_packets if total_packets else 0

    return {
        'total_packets': total_packets,
        'packet_type_percentages': packet_type_percentages,
        'average_packet_size': average_packet_size
    }




def main():
     
    # Example file path containing the packet data
    file_path = 'captured_packets/capturecapture2.txt'

    # Analyze the packets
    stats = analyze_packets(file_path)

    # Display the statistics
    print(f"Total Packets: {stats['total_packets']}")
    print("Packet Type Percentages:")
    for packet_type, percentage in stats['packet_type_percentages'].items():
        print(f"  {packet_type}: {percentage:.2f}%")
    print(f"Average Packet Size: {stats['average_packet_size']:.2f} bytes")

if __name__ == "__main__":
    main()