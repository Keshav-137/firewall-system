from scapy.all import *
import time

# Define target IP and port
target_ip = "202.39.224.7"
target_port = 80  # Common HTTP port for testing

# Malicious payload examples (simulating malware, exploit, and unauthorized access)
malicious_payloads = [
    "malware: Trojan detected!",
    "exploit: buffer overflow attempt",
    "unauthorized_access: admin access attempt"
]

# Function to send malicious packets
def send_malicious_packet(payload, count):
    packet = IP(dst=target_ip) / TCP(dport=target_port, flags="S") / Raw(load=payload)
    send(packet)
    print(f"Sent malicious packet with payload: {payload}")
    count += 1  # Increment the count after sending the packet
    return count

# Counter for malicious packets
malicious_count = 0

# Send packets with malicious payloads
for payload in malicious_payloads:
    malicious_count = send_malicious_packet(payload, malicious_count)
    time.sleep(1)  # Wait for a short duration before sending the next packet

# Simulate a flooding attack by sending too many packets from an unauthorized source
def send_flooding_attack():
    source_ip = "192.168.72.150"  # An IP address used for flooding attempts
    flooding_count = 0  # Counter for flooding packets
    for _ in range(20):  # Send 20 packets in a short time span to simulate flooding
        packet = IP(src=source_ip, dst=target_ip) / TCP(dport=target_port, flags="S")
        send(packet)
        flooding_count += 1  # Increment the flooding packet count
        time.sleep(0.2)  # Small delay between packets
    return flooding_count

# Send a flooding attack and count the sent packets
flooding_count = send_flooding_attack()

# Print the total counts for both types of packets
print(f"Total malicious packets sent: {malicious_count}")
print(f"Total flooding attack packets sent: {flooding_count}")
