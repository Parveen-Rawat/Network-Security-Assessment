import os
import re
import nmap
import ipaddress

# Define storage path dynamically based on the current user
storage_path = os.path.join(os.path.expanduser("~"), "Storage")
os.makedirs(storage_path, exist_ok=True)  # Ensure the directory exists

# Regex pattern to check port range format
port_range_pattern = re.compile(r"^(\d+)-(\d+)$")

port_min = 0
port_max = 65535  # Max valid port number

# ASCII Banner
print(r"""

 __ _     ____     _  ___           
/ _\ |__ |___ \ __| |/ _ \__      __
\ \| '_ \  __) / _` | | | \ \ /\ / /
_\ \ | | |/ __/ (_| | |_| |\ V  V / 
\__/_| |_|_____\__,_|\___/  \_/\_/  
                                    

""")

# Validate IP address
while True:
    ip_add_entered = input("\nEnter the IP address to scan: ")
    try:
        ip_address_obj = ipaddress.ip_address(ip_add_entered)
        print("Valid IP address entered.")
        break
    except ValueError:
        print("Invalid IP address. Please try again.")

# Validate port range
while True:
    port_range = input("Enter port range (e.g., 20-80): ")
    port_range_valid = port_range_pattern.match(port_range.replace(" ", ""))
    if port_range_valid:
        port_min = int(port_range_valid.group(1))
        port_max = int(port_range_valid.group(2))
        if 0 <= port_min <= port_max <= 65535:
            break
        else:
            print("Port numbers must be between 0 and 65535.")
    else:
        print("Invalid port range format. Please enter as <low>-<high>.")

# Initialize Nmap scanner
nm = nmap.PortScanner()

# Define file paths for different formats
scan_output_xml = os.path.join(storage_path, "scan_results.xml")
scan_output_normal = os.path.join(storage_path, "scan_results.nmap")
scan_output_grepable = os.path.join(storage_path, "scan_results.gnmap")

try:
    # Run nmap scan (without `-oX`, `-oN`, or `-oG`)
    print("\nScanning in progress...\n")
    nm.scan(ip_add_entered, f"{port_min}-{port_max}", arguments="-sS -A")

    # Check if scanning was successful
    if nm.all_hosts():
        print("Scan complete. Saving results...")

        # Save XML output
        with open(scan_output_xml, "w") as xml_file:
            xml_file.write(nm.get_nmap_last_output())

        # Save Normal output
        with open(scan_output_normal, "w") as normal_file:
            normal_file.write(str(nm.scaninfo()))

        # Save Grepable output
        with open(scan_output_grepable, "w") as grepable_file:
            for host in nm.all_hosts():
                grepable_file.write(f"{host} {nm[host]}\n")

        print(f"Scan results saved in:\n - XML: {scan_output_xml}\n - Normal: {scan_output_normal}\n - Grepable: {scan_output_grepable}")

    else:
        print("No hosts found. Scan might have failed or the target is not responding.")

except Exception as e:
    print(f"Error while scanning: {e}")
