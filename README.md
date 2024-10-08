# Network Packet Sniffer and Analyzer

A Python-based Network Packet Sniffer and Analysis Tool built with `Tkinter` for the GUI, `Scapy` for packet capturing, and `Matplotlib` for real-time traffic visualization. This tool allows you to capture and filter network traffic, display TCP/UDP/ICMP statistics, view packet payloads, and save captured packets to a `.pcap` file for later analysis.

## Features

- **Capture All Packets**: Sniff all network packets and display the packet details (source IP, destination IP, TCP/UDP ports, and payload).
- **Protocol-based Filtering**: Filter packets by protocol (`TCP`, `UDP`, or `ICMP`) for targeted analysis.
- **IP-based Filtering**: Capture packets to/from a specific IP address.
- **Real-Time Traffic Visualization**: Visualize live packet traffic statistics (TCP, UDP, ICMP) with dynamic graphs.
- **Save Packets to PCAP**: Capture packets and save them in a `.pcap` file format for further analysis in tools like Wireshark.
- **User-Friendly GUI**: Built using `Tkinter`, making it easy to use for both beginners and professionals.

## Prerequisites

Make sure you have the following installed:

- Python 3.x
- Tkinter (for the GUI)
- Scapy (for packet sniffing and network analysis)
- Matplotlib (for real-time graph plotting)

You can install the required dependencies using pip:

```bash
pip install scapy matplotlib
