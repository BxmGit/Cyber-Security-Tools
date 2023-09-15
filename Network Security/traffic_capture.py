"""
This Traffic Capture is intended for educational purposes and ethical use only. 
Do not use this code to perform any unauthorized or illegal activities. 
Scanning networks or systems without explicit permission is illegal in many jurisdictions. 
The author of this repository is not responsible for any misuse of this software. 
By using this software, you agree to adhere to all applicable laws and regulations, and you accept full liability for your actions.
"""

"""
REQUIREMENTS:
    What does the program need to do? Capture packets of data coming into the network. Filters. Analysis. Storage. Security Analysis. Visualisation.
    What kind of information should we gather? Source, Destination, content, Where is it coming from? Who is accessing the service?
    What librarys and modules should we use? scapy, pyshark, pcapy
    Further advancements such as analysis, ML anomaly detection and alerts. 

    General monitoring: time, destination ips and source ips, ports (add port information), packet size and payloads, flag information. 
    Possible Use cases: view data being used. Port scanner detection, MITM atacks, Dos/DDoS, Intrusion detection, Geographical Locations, Application Level Attacks. 
    Further enhancements for security
"""


from scapy.all import sniff, IP, TCP
import json
from datetime import datetime, timedelta
import csv
from collections import defaultdict
from geoip2.database import Reader
from ipaddress import ip_address, ip_network
import pyfiglet


LOCAL_NETWORKS = ["192.168.1.0/24", "10.0.0.0/24"]
port_scan_detect = defaultdict(lambda: defaultdict(list))
geoip_reader = Reader('..\\useful_files\\GeoLite2-City.mmdb')


def menu():
    print("Select Mode:")
    print("1: Generic Traffic Capture to JSON")
    print("2: Port Scanner Detection Mode")
    return input("Enter the number of your choice: ")


def load_ports_from_csv(filename):
    port_dict = {}
    with open(filename, 'r') as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            port_dict[int(row['port'])] = row['description']
    return port_dict


def append_to_json_file(data, filename='packet_capture.json'):
    try:
        with open(filename, 'r') as f:
            existing_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        existing_data = []

    existing_data.append(data)

    with open(filename, 'w') as f:
        json.dump(existing_data, f, indent=4)


def is_local_ip(ip):
    for network in LOCAL_NETWORKS:
        if ip_address(ip) in ip_network(network):
            return True
    return False


def get_geolocation(ip):
    try:
        location = geoip_reader.city(ip)
        return {
            'country': location.country.name,
            'city': location.city.name,
            'latitude': location.location.latitude,
            'longitude': location.location.longitude
        }
    except:
        return None

def detect_port_scanning(ip, port, port_descriptions):
    global port_scan_detect
    time_now = datetime.now()

    # Remove outdated entries
    port_scan_detect[ip][port] = [
        time for time in port_scan_detect[ip][port] if time_now - time <= timedelta(seconds=5)
    ]

    # Add new entry
    port_scan_detect[ip][port].append(time_now)

    # Check if the number of ports accessed within the last 5 seconds is suspiciously high (e.g., more than 10)
    suspicious_ports = [
        port for port, times in port_scan_detect[ip].items() if len(times) > 10
    ]

    if suspicious_ports:
        print(f"Possible port scanning detected from {ip} on ports {suspicious_ports}")
        for port in suspicious_ports:
            description = port_descriptions.get(port, "Unknown")
            print(f"Port: {port}, Service: {description}")
        # Clear the records for these suspicious ports
        for port in suspicious_ports:
            del port_scan_detect[ip][port]

def process_incoming_packet_generic(packet, port_descriptions):
    if IP in packet:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        direction = "Outbound" if is_local_ip(source_ip) and not is_local_ip(destination_ip) else "Inbound"

        source_port = None
        destination_port = None
        source_port_description = None
        destination_port_description = None
        packet_size = None
        packet_flags = None
        payload = None
        possible_port_scan = False

        source_geolocation = get_geolocation(source_ip)
        destination_geolocation = get_geolocation(destination_ip)

        if TCP in packet:
            source_port = packet[TCP].sport
            source_port_description = port_descriptions.get(source_port, "Unknown")
            destination_port = packet[TCP].dport
            destination_port_description = port_descriptions.get(destination_port, "Unknown")
            packet_size = len(packet)
            packet_flags = packet.sprintf('%TCP.flags%')
            payload = str(packet[TCP].payload)

            # Detect port scanning and set flag
            detect_port_scanning(source_ip, source_port, port_descriptions)
            suspicious_ports = [
                port for port, times in port_scan_detect[source_ip].items() if len(times) > 10
            ]
            if suspicious_ports:
                possible_port_scan = True
                print(f"Possible port scanning detected from {source_ip} on ports {suspicious_ports}")
                for port in suspicious_ports:
                    description = port_descriptions.get(port, "Unknown")
                    print(f"Port: {port}, Service: {description}")

        packet_data = {
            "Timestamp": timestamp,
            "Direction": direction,
            "Source_IP": source_ip,
            "Dest_IP": destination_ip,
            "Source_Port": source_port,
            "Source_Port_Description": source_port_description,
            "Dest_Port": destination_port,
            "Dest_Port_Description": destination_port_description,
            "Packet_Size": packet_size,
            "TCP_Flags": packet_flags,
            "Payload": payload,
            "Source_Geolocation": source_geolocation,
            "Destination_Geolocation": destination_geolocation,
            "Possible_Port_Scan": possible_port_scan
        }

        append_to_json_file(packet_data)

def process_incoming_packet_port_scan(packet):
    if IP in packet and TCP in packet:
        source_ip = packet[IP].src
        source_port = packet[TCP].sport
        detect_port_scanning(source_ip, source_port)

def main():
    ascii_banner = pyfiglet.figlet_format("BxmGit Traffic Capture")
    print(ascii_banner)

    port_descriptions = load_ports_from_csv('..\\useful_files\\list_of_ports_and_services.csv')
    interface = 'Ethernet'
    
    choice = menu()
    
    if choice == '1':
        print("Running in Generic Traffic Capture to JSON mode...")
        sniff(iface=interface, prn=lambda packet: process_incoming_packet_generic(packet, port_descriptions))
        
    elif choice == '2':
        print("Running in Port Scanner Detection mode...")
        sniff(iface=interface, prn=process_incoming_packet_port_scan)
        
    else:
        print("Invalid choice. Exiting.")


if __name__ == "__main__":
    main()