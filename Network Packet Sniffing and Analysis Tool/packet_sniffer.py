# Importing necessary modules
from scapy.all import sniff, TCP, UDP, ICMP, IP, wrpcap
from collections import defaultdict
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation

# Dictionary to hold packet statistics
packet_stats = defaultdict(int)

# Function to process captured packets
def process_packet(packet):
    if packet.haslayer(IP):  # Check if the packet has an IP layer
        src_ip = packet['IP'].src  # Extract source IP
        dst_ip = packet['IP'].dst  # Extract destination IP
        protocol = packet['IP'].proto  # Get protocol number
        
        # Update statistics based on protocol type
        if packet.haslayer(TCP):
            packet_stats['TCP'] += 1
        elif packet.haslayer(UDP):
            packet_stats['UDP'] += 1
        elif packet.haslayer(ICMP):
            packet_stats['ICMP'] += 1
        else:
            packet_stats['Other'] += 1
        
        # Print basic packet details
        print(f"Packet captured: Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol}")
        
        # Check if the packet is TCP and display TCP-specific details
        if packet.haslayer(TCP):
            src_port = packet['TCP'].sport  # Source port
            dst_port = packet['TCP'].dport  # Destination port
            print(f"TCP Packet: Source Port: {src_port}, Destination Port: {dst_port}")
        
        # Display payload if available
        if packet.haslayer('Raw'):
            payload = packet['Raw'].load  # Extract payload
            print(f"Payload: {payload}")
        
        # Print the updated packet statistics
        print_packet_stats()

# Function to print packet statistics in real-time
def print_packet_stats():
    print("\n[ Real-Time Packet Statistics ]")
    for protocol, count in packet_stats.items():
        print(f"{protocol}: {count} packets")
    print("--------------------------\n")

# Function to update the graph in real-time
def update_graph(i):
    protocols = ['TCP', 'UDP', 'ICMP', 'Other']
    counts = [packet_stats[protocol] for protocol in protocols]

    ax.clear()  # Clear previous graph
    ax.bar(protocols, counts, color=['blue', 'green', 'red', 'orange'])  # Bar plot
    ax.set_xlabel('Protocol')
    ax.set_ylabel('Number of Packets')
    ax.set_title('Real-Time Packet Capture Statistics')

# Function to capture and filter packets based on protocol or IP
def capture_filtered_packets(filter_type=None, target_ip=None, packet_count=100):
    # If filtering by protocol
    if filter_type:
        print(f"Capturing {filter_type.upper()} packets... Press Ctrl+C to stop.")
        sniff(filter=filter_type, prn=process_packet, store=False, count=packet_count)

    # If filtering by IP
    elif target_ip:
        print(f"Capturing packets to/from {target_ip}... Press Ctrl+C to stop.")
        sniff(filter=f"host {target_ip}", prn=process_packet, store=False, count=packet_count)

    # Capture all packets
    else:
        print(f"Capturing all packets... Press Ctrl+C to stop.")
        sniff(prn=process_packet, store=False, count=packet_count)

# Function to save captured packets to a PCAP file
def save_packets_to_pcap(packet_count=100, filename="captured_traffic.pcap"):
    print(f"Capturing {packet_count} packets and saving to {filename}")
    packets = sniff(count=packet_count)  # Capture packets
    wrpcap(filename, packets)  # Save to PCAP file
    print(f"Packets saved to {filename}")

# Function to capture packets and display a real-time graph
def capture_packets_with_graph(packet_count=100):
    print(f"Capturing packets... Press Ctrl+C to stop.")
    
    # Setup matplotlib animation for real-time graph
    global ani  # Make sure the animation object persists
    ani = FuncAnimation(plt.gcf(), update_graph, interval=1000)  # Update graph every 1 second
    
    plt.show(block=False)  # Non-blocking show
    
    sniff(prn=process_packet, store=False, count=packet_count)  # Capture packets

# Main function to run the packet sniffer
def run_packet_sniffer():
    # Choose mode of operation
    print("Choose mode of operation:")
    print("1. Capture and filter TCP packets")
    print("2. Capture packets to/from a specific IP")
    print("3. Capture all packets and display payload")
    print("4. Capture packets and save to PCAP file")
    print("5. Capture packets with real-time graph visualization")
    
    choice = input("Enter your choice (1-5): ")
    
    if choice == '1':
        capture_filtered_packets(filter_type="tcp", packet_count=100)  # Capture TCP packets
    
    elif choice == '2':
        target_ip = input("Enter the IP address to filter: ")
        capture_filtered_packets(target_ip=target_ip, packet_count=100)  # Capture packets to/from IP
    
    elif choice == '3':
        capture_filtered_packets(packet_count=100)  # Capture all packets and display payload
    
    elif choice == '4':
        filename = input("Enter the filename to save PCAP (e.g., captured_traffic.pcap): ")
        save_packets_to_pcap(packet_count=100, filename=filename)  # Save packets to file
    
    elif choice == '5':
        # Initialize the plot for real-time graph visualization
        global fig, ax, ani
        fig, ax = plt.subplots()
        capture_packets_with_graph(packet_count=100)  # Capture packets with graph

    else:
        print("Invalid choice. Exiting.")

# Start the packet sniffer
if __name__ == "__main__":
    run_packet_sniffer()
