from scapy.all import *
import argparse

# Create the argument parser
parser = argparse.ArgumentParser(description="this script sends a TCP packet from one 1 host to the other")

# Add arguments
parser.add_argument('-s', '--sender', required=True, help="h1 or h2 or h3")
parser.add_argument('-d', '--dst_ip', required=True, help="destination IP")

# Parse the arguments
args = parser.parse_args()
# Extract the arguments
sender = args.sender
dst_ip = args.dst_ip
# Print the result
print(f"Sender: {sender}")
print(f"Destination IP: {dst_ip}")

def extract_third_octet(ip_address):
    try:
        # Split the IP address into octets
        octets = ip_address.split('.')
        
        # Check if the IP address has exactly 4 octets
        if len(octets) != 4:
            raise ValueError("Invalid IPv4 address")
        
        # Extract the third octet
        third_octet = octets[2]
        
        return third_octet
    except Exception as e:
        return str(e)

if sender == 'h1':
    interface = 'dtap0'  # Replace with the actual network interface
elif sender == 'h2':
    interface = 'dtap1'  # Replace with the actual network interface
elif sender == 'h3':
    interface = 'dtap2'  # Replace with the actual network interface
# print('The sending interface is', interface)

network = extract_third_octet(dst_ip)
# print(f"The third octet of {dst_ip} is {network}")

if network == '10':
    target_mac = '00:00:00:00:00:01'  # Replace with the actual target MAC
    target_port = 80  # Replace with the actual target port
elif network == '20':
    target_mac = '00:00:00:00:00:02'  # Replace with the actual target MAC
    target_port = 80  # Replace with the actual target port
elif network == '30':
    target_mac = '00:00:00:00:00:03'  # Replace with the actual target MAC
    target_port = 80  # Replace with the actual target port


# packet_header == 'eth/ipv4/tcp':
# Create an Ethernet frame and TCP packet
packet_tcp = Ether(dst=target_mac) / IP(dst=dst_ip, proto=6)
# Send the packet_tcp on the specified interface
sendp(packet_tcp, iface=interface)