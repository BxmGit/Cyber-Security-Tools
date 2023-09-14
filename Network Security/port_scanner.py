# PORT SCANNER WHICH CAN SCAN IPs or URLS
# USER SELECTS THE TYPE OF SCAN THEY WANT: Quick Scan, Full Scan or Custom Scan.
# USER SELECTS THE SPEED OF SCAN.

"""
This Port Scanner is intended for educational purposes and ethical use only. 
Do not use this code to perform any unauthorized or illegal activities. 
Scanning networks or systems without explicit permission is illegal in many jurisdictions. 
The author of this repository is not responsible for any misuse of this software. 
By using this software, you agree to adhere to all applicable laws and regulations, and you accept full liability for your actions.
"""

# =====================================================================================================================================
# IMPORTS AND MODULES
# =====================================================================================================================================

from concurrent.futures import ThreadPoolExecutor  # For threading
import socket  # For network operations
import pyfiglet  # For generating ASCII art banners
import csv  # For reading from CSV files

# =====================================================================================================================================
# FUNCTION DEFINITIONS
# =====================================================================================================================================

# Function to load ports from a CSV file into a list
def load_ports_from_csv(filename):
    """Load port information from a given CSV file.

    Parameters:
        filename (str): Path to the CSV file.

    Returns:
        list: A list of dictionaries containing port information.
    """
    port_list = []
    with open(filename, mode="r", encoding="utf-8") as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            port_list.append(row)
    return port_list

# Function to scan a single port
def scan_port(host, port, protocol, description):
    """Scan a single port on a given host.

    Parameters:
        host (str): The host to scan.
        port (str): The port number to scan.
        protocol (str): The protocol used by the port.
        description (str): Description of the port.

    Returns:
        dict: A dictionary containing open port details, or None if the port is closed.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((host, int(port)))
    sock.close()
    if result == 0:
        return {"port": port, "protocol": protocol, "description": description}
    return None

# Function to select scan size (Quick, Full, Custom)
def scan_size():
    """Ask the user to select the type of scan to perform.

    Returns:
        list: A list of dictionaries containing port information to scan, or None to exit.
    """
    all_ports = load_ports_from_csv("..\\useful_files\\list_of_ports_and_services.csv")
    while True:
        scan_type = input("Scan types: \n  - a. Quick Scan: Frequently used ports. \n  - b. Full Scan: Scan all ports. \n  - c. Custom Scan: Enter your specified port range you want to scan. \nPlease enter the type of scan you would like to conduct or exit with 'q': ")
        if scan_type.lower() == "q":
            print("Exiting Scanner.")
            break
        elif scan_type.lower() not in ["a", "b", "c"]:
            print("Invalid selection. Please try again.")
        else:
            if scan_type == "a":
                quick_scan_list = load_ports_from_csv("..\\useful_files\\top_1000_ports.csv")
                return quick_scan_list
            elif scan_type == "b":
                return all_ports
            elif scan_type == "c":
                start_port = int(input("Please enter the start port number: "))
                end_port = int(input("Please enter the end port number: "))
                custom_scan_list = [row for row in all_ports if start_port <= int(row["port"]) <= end_port]
                return custom_scan_list

# Function to resolve a domain name to its IP address
def resolve_domain(domain_name):
    """Resolve a domain name to an IP address.

    Parameters:
        domain_name (str): The domain name to resolve.

    Returns:
        str: The resolved IP address, or None if resolution fails.
    """
    try:
        return socket.gethostbyname(domain_name)
    except socket.gaierror:
        return None

# Function to select scan speed
def select_scan_speed():
    """Ask the user to select the scan speed (Slow, Medium, Fast).

    Returns:
        int: The number of threads to use for the scan.
    """
    while True:
        try:
            speed_option = input("Select the scan speed: \n  - a. Slow \n  - b. Medium \n  - c. Fast \nEnter your choice: ").lower()
            if speed_option == 'a':
                return 10
            elif speed_option == 'b':
                return 50
            elif speed_option == 'c':
                return 100
            else:
                print("Invalid selection. Please try again.")
        except ValueError:
            print("Invalid input. Please enter a valid option.")

# =====================================================================================================================================
# MAIN FUNCTION
# =====================================================================================================================================

if __name__ == "__main__":
    # Display a banner using pyfiglet
    ascii_banner = pyfiglet.figlet_format("PORT SCANNER for IPs and URLs.")
    print(ascii_banner)
    
    # Get scan information from the user
    scan_info = scan_size()
    
    # Get scan speed from the user
    num_threads = select_scan_speed()

    # Continue only if scan_info is valid
    if scan_info is not None:
        host_input = input("Please enter the IP address or URL you'd like to scan: ")
        host = resolve_domain(host_input) if not host_input.replace(".", "").isnumeric() else host_input

        # Check if the host is resolved successfully
        if host:
            open_ports = []
            
            # Use ThreadPoolExecutor for concurrent scanning
            with ThreadPoolExecutor(max_workers=num_threads) as executor:
                futures = [executor.submit(scan_port, host, row["port"], row["protocol"], row["description"]) for row in scan_info]
                for future in futures:
                    result = future.result()
                    if result:
                        open_ports.append(result)

            # Display scan results
            if open_ports:
                print(f"Open ports on {host}:")
                for port_info in open_ports:
                    print(f"Port: {port_info['port']}, Protocol: {port_info['protocol']}, Description: {port_info['description']}")
            else:
                print(f"No open ports found on {host}.")
        else:
            print(f"Could not resolve {host_input}.")
    else:
        print("Exiting scanner.")
