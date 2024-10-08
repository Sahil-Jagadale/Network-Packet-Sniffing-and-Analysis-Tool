Network Packet Sniffer and Analyzer
A Python-based Network Packet Sniffer and Analysis Tool built with Tkinter for the GUI, Scapy for packet capturing, and Matplotlib for real-time traffic visualization. This tool allows you to capture and filter network traffic, display TCP/UDP/ICMP statistics, view packet payloads, and save captured packets to a .pcap file for later analysis.

Features
Capture All Packets: Sniff all network packets and display the packet details (source IP, destination IP, TCP/UDP ports, and payload).
Protocol-based Filtering: Filter packets by protocol (TCP, UDP, or ICMP) for targeted analysis.
IP-based Filtering: Capture packets to/from a specific IP address.
Real-Time Traffic Visualization: Visualize live packet traffic statistics (TCP, UDP, ICMP) with dynamic graphs.
Save Packets to PCAP: Capture packets and save them in a .pcap file format for further analysis in tools like Wireshark.
User-Friendly GUI: Built using Tkinter, making it easy to use for both beginners and professionals.
Prerequisites
Make sure you have the following installed:

Python 3.x
Tkinter (for the GUI)
Scapy (for packet sniffing and network analysis)
Matplotlib (for real-time graph plotting)
You can install the required dependencies using pip:

bash
Copy code
pip install scapy matplotlib
How to Run
Clone the repository:

bash
Copy code
git clone https://github.com/your-username/network-packet-sniffer.git
cd network-packet-sniffer
Run the main script:

bash
Copy code
python packet_sniffer.py
The GUI window will open, allowing you to choose from the following options:

Capture TCP Packets: Capture and analyze TCP packets.
Capture Packets by IP: Capture packets to/from a specific IP address.
Capture All Packets and Display Payload: Capture all packets and show their payloads (if available).
Capture Packets and Save to PCAP: Capture packets and save them to a .pcap file.
Visualize Real-Time Traffic: Display real-time traffic statistics in a graph format (TCP, UDP, ICMP counts).
Once you are done, you can exit the tool by clicking the "Exit" button.

Project Structure
bash
Copy code
network-packet-sniffer/
│
├── packet_sniffer.py          # Main script to run the application
├── README.md                  # Project README file
└── requirements.txt           # Dependencies for the project
Screenshots

Future Enhancements
Advanced Packet Filtering: Add advanced filtering options such as by port number or packet size.
Detailed Packet Analysis: Add deeper packet analysis to display full packet contents (headers, flags, etc.).
Historical Traffic Analysis: Implement features to analyze saved PCAP files within the tool.
Contributions
Contributions are welcome! If you'd like to enhance this tool, feel free to fork the repository and create a pull request with your changes.

License
This project is licensed under the MIT License - see the LICENSE file for details.

Acknowledgements
Scapy Documentation
Matplotlib Documentation
