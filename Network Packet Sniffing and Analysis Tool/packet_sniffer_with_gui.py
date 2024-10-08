import tkinter as tk
from scapy.all import sniff, TCP, UDP, ICMP, IP, wrpcap
from collections import defaultdict
from matplotlib.animation import FuncAnimation
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# Packet statistics
packet_stats = defaultdict(int)

# Sniffer function to process captured packets
def process_packet(packet):
    if packet.haslayer(IP):
        if packet.haslayer(TCP):
            packet_stats['TCP'] += 1
        elif packet.haslayer(UDP):
            packet_stats['UDP'] += 1
        elif packet.haslayer(ICMP):
            packet_stats['ICMP'] += 1
        else:
            packet_stats['Other'] += 1

        # Print packet details for the console
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        print(f"Packet captured: Source IP: {src_ip}, Destination IP: {dst_ip}")

        # Check if the packet is TCP and display TCP-specific details
        if packet.haslayer(TCP):
            src_port = packet['TCP'].sport
            dst_port = packet['TCP'].dport
            print(f"TCP Packet: Source Port: {src_port}, Destination Port: {dst_port}")

        # Display payload if available
        if packet.haslayer('Raw'):
            payload = packet['Raw'].load
            print(f"Payload: {payload}")

def capture_filtered_packets(filter_type=None, target_ip=None):
    if filter_type:
        print(f"Capturing {filter_type.upper()} packets... Press Ctrl+C to stop.")
        sniff(filter=filter_type, prn=process_packet, store=False)
    elif target_ip:
        print(f"Capturing packets to/from {target_ip}... Press Ctrl+C to stop.")
        sniff(filter=f"host {target_ip}", prn=process_packet, store=False)
    else:
        print("Capturing all packets... Press Ctrl+C to stop.")
        sniff(prn=process_packet, store=False)

def save_packets_to_pcap(packet_count=100, filename="captured_traffic.pcap"):
    print(f"Capturing {packet_count} packets and saving to {filename}")
    packets = sniff(count=packet_count)  # Capture packets
    wrpcap(filename, packets)  # Save to PCAP file
    print(f"Packets saved to {filename}")

def create_main_window():
    root = tk.Tk()
    root.title("Packet Sniffer GUI")
    root.geometry("500x500")
    
    title_label = tk.Label(root, text="Network Packet Sniffer", font=("Helvetica", 16))
    title_label.pack(pady=10)
    
    return root

def add_ui_components(root):
    tcp_button = tk.Button(root, text="Capture TCP Packets", command=lambda: capture_filtered_packets(filter_type="tcp"))
    tcp_button.pack(pady=10)

    ip_label = tk.Label(root, text="Enter IP to filter:")
    ip_label.pack(pady=5)
    
    ip_entry = tk.Entry(root)
    ip_entry.pack(pady=5)
    
    ip_button = tk.Button(root, text="Capture Packets by IP", command=lambda: capture_filtered_packets(target_ip=ip_entry.get()))
    ip_button.pack(pady=10)

    all_packets_button = tk.Button(root, text="Capture All Packets and Display Payload", command=capture_filtered_packets)
    all_packets_button.pack(pady=10)

    save_button = tk.Button(root, text="Capture Packets and Save to PCAP", command=lambda: save_packets_to_pcap(packet_count=100))
    save_button.pack(pady=10)

    graph_button = tk.Button(root, text="Visualize Real-Time Traffic", command=lambda: start_real_time_graph(root))
    graph_button.pack(pady=10)

    exit_button = tk.Button(root, text="Exit", command=root.quit)
    exit_button.pack(pady=20)

def create_graph_canvas(root):
    fig, ax = plt.subplots()
    canvas = FigureCanvasTkAgg(fig, master=root)
    canvas.draw()
    canvas.get_tk_widget().pack(pady=20)
    return fig, ax, canvas

def update_graph_ui(i, ax, canvas):
    protocols = ['TCP', 'UDP', 'ICMP', 'Other']
    counts = [packet_stats[protocol] for protocol in protocols]
    ax.clear()
    ax.bar(protocols, counts, color=['blue', 'green', 'red', 'orange'])
    ax.set_xlabel('Protocol')
    ax.set_ylabel('Number of Packets')
    ax.set_title('Real-Time Packet Capture Statistics')
    canvas.draw()

def start_real_time_graph(root):
    fig, ax, canvas = create_graph_canvas(root)
    ani = FuncAnimation(fig, update_graph_ui, fargs=(ax, canvas), interval=1000)
    root.ani = ani  # Store the reference to prevent garbage collection

def start_gui():
    root = create_main_window()
    add_ui_components(root)
    root.mainloop()

# Start the GUI
if __name__ == "__main__":
    start_gui()
