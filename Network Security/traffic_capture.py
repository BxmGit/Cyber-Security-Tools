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

# ================================================================
# IMPORTS AND DECLARATIONS
# ================================================================
from scapy.all import sniff, IP, TCP
import json
import datetime
import csv
from geoip2.database import Reader

# ================================================================
# FUNCTIONS
# ================================================================

# Initialize GeoIP reader
geoip_reader = Reader('..\\useful_files\\GeoLite2-City.mmdb')

# Function to get geolocation info for an IP address
def get_geolocation(ip_address):
    try:
        location = geoip_reader.city(ip_address)
        return {
            'country': location.country.name,
            'city': location.city.name,
            'latitude': location.location.latitude,
            'longitude': location.location.longitude
        }
    except:
        return None

# Load port information from CSV into a dictionary
def load_ports_from_csv(filename):
    port_dict = {}
    with open(filename, 'r') as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            port_dict[int(row['port'])] = row['description']
    return port_dict

# Create or open the JSON file for appending
def append_to_json_file(data, filename='packet_capture.json'):
    try:
        with open(filename, 'r') as f:
            existing_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        existing_data = []

    existing_data.append(data)

    with open(filename, 'w') as f:
        json.dump(existing_data, f, indent=4)

# Function to process incoming packets
def process_incoming_packet(packet):
    if IP in packet:
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        source_port = None
        destination_port = None
        source_port_description = None
        destination_port_description = None
        packet_size = None
        packet_flags = None
        payload = None
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
            

        packet_data = {
            "Timestamp": timestamp,
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
            "Destination_Geolocation": destination_geolocation
        }

        append_to_json_file(packet_data)

# Main code
port_descriptions = load_ports_from_csv('..\\useful_files\\list_of_ports_and_services.csv')  # Replace with the path to your CSV file
interface = 'Ethernet'  # Replace this with your relevant network interface
sniff(iface=interface, prn=process_incoming_packet)