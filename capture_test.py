# capture_test.py
from core.utils.capture import construct_tcpdump_capture_commands, run_tcpdump_capture_commands

if __name__ == "__main__":
    iface = "en0"  # replace with your network interface
    num_packets = 10
    capture_name = "test1"

    cmd1, cmd2, pcap_file, txt_file = construct_tcpdump_capture_commands(
        capture_name=capture_name,
        user_interface=iface,
        num_packets=num_packets
    )

    run_tcpdump_capture_commands(cmd1, cmd2, pcap_file, txt_file)
    print(f"PCAP saved at {pcap_file}")
    print(f"Text capture saved at {txt_file}")