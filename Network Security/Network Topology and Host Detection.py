from scapy.all import ARP, Ether, srp, sniff, IP
from collections import defaultdict
import networkx as nx
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
from geoip2.database import Reader

# Initialize Network Graph
network_graph = nx.Graph()

# Live Host Detection
def arp_scan(ip_range):
    hosts = []
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
    ans, _ = srp(packet, timeout=2, verbose=False)
    
    for _, rcv in ans:
        hosts.append(rcv.psrc)
    
    return hosts

# Data Collection & Analysis
def packet_callback(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst

        if src not in network_graph.nodes():
            network_graph.add_node(src)
        if dst not in network_graph.nodes():
            network_graph.add_node(dst)
        if not network_graph.has_edge(src, dst):
            network_graph.add_edge(src, dst)

# Topology Visualization
def plot_network_topology():
    pos = nx.spring_layout(network_graph)
    labels = {node: node for node in network_graph.nodes()}
    nx.draw(network_graph, pos, labels=labels, with_labels=True)
    plt.show()

# Main function
if __name__ == "__main__":
    live_hosts = arp_scan("192.168.1.0/24")  # Replace with your network range
    print(f"Live Hosts: {live_hosts}")

    print("Starting packet capture. Press Ctrl+C to stop and plot network topology.")
    try:
        sniff(prn=packet_callback, filter="ip", store=0)
    except KeyboardInterrupt:
        print("Stopping packet capture.")
        print("Plotting network topology.")
        plot_network_topology()
