import joblib
from scapy.all import *
import logging
import time
import warnings
import numpy as np

# Suppress sklearn warnings
warnings.filterwarnings("ignore", category=UserWarning)

# Load the pre-trained model
model = joblib.load("firewall_model.pkl")

# Configure logging
logging.basicConfig(filename="firewall.log", level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Threat signatures for payload inspection (expanded)
THREAT_SIGNATURES = ["malware", "exploit", "unauthorized_access", "backdoor", "virus", "ransomware"]

# Track IP activity to detect suspicious behavior (flooding)
connection_tracker = {}

# List of known malicious IPs for reputation-based blocking (example)
MALICIOUS_IP_LIST = ["192.168.72.100", "203.0.113.0"]  # Replace with real list or dynamic source

# Function to log blocked packets
def log_blocked_packet(reason, src_ip, dst_ip):
    logging.warning(f"Blocked: {src_ip} -> {dst_ip} | Reason: {reason}")
    print(f"Blocked: {src_ip} -> {dst_ip} | Reason: {reason}")

# Function to log allowed packets
def log_allowed_packet(src_ip, dst_ip):
    logging.info(f"Allowed: {src_ip} -> {dst_ip}")
    print(f"Allowed: {src_ip} -> {dst_ip}")

# Function to log detected threats
def log_threat(threat_type, src_ip):
    logging.warning(f"Threat Detected: {threat_type} from {src_ip}")
    print(f"Threat Detected: {threat_type} from {src_ip}")

# Function to check IP reputation
def check_ip_reputation(src_ip):
    if src_ip in MALICIOUS_IP_LIST:
        log_threat("Blocked IP (Known Malicious)", src_ip)
        return False
    return True

# Function to check for suspicious activity (flooding)
def behavior_analysis(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        current_time = time.time()

        # Track connection attempts
        if src_ip not in connection_tracker:
            connection_tracker[src_ip] = []
        connection_tracker[src_ip].append(current_time)

        # Keep only recent attempts (last 10 seconds)
        connection_tracker[src_ip] = [t for t in connection_tracker[src_ip] if current_time - t < 10]

        # Block if IP exceeds 10 attempts in 10 seconds (Flooding detection)
        if len(connection_tracker[src_ip]) > 10:
            log_blocked_packet("Suspicious Activity (Flooding)", src_ip, dst_ip)
            return False
    return True

# Function to inspect packets with the ML model
def inspect_with_ml(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        payload_size = len(packet[Raw].load) if packet.haslayer(Raw) else 0

        # Extract features for the model
        features = np.array([[protocol, payload_size]])
        prediction = model.predict(features)[0]

        if prediction == "malicious":
            log_blocked_packet("ML Detected Threat", src_ip, dst_ip)
            return False
    return True

# Function to inspect packet payload for threat signatures
def inspect_payload(packet):
    if packet.haslayer(Raw):  # Inspect packet payload
        payload = packet[Raw].load.decode(errors="ignore")
        for signature in THREAT_SIGNATURES:
            if signature in payload:
                log_blocked_packet("Malicious Payload Detected", packet[IP].src, packet[IP].dst)
                return False
    return True

# Function to inspect packets
def inspect_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Check if the IP reputation is good
        if not check_ip_reputation(src_ip):
            log_blocked_packet("IP Reputation Blocked", src_ip, dst_ip)
            return False
        
        # Inspect packet payload for known signatures
        if not inspect_payload(packet):
            return False
        
        # Inspect packet using machine learning model
        if not inspect_with_ml(packet):
            return False

    return True

# Unified packet handler
def packet_handler(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Perform behavior analysis (e.g., flood detection)
        if not behavior_analysis(packet):
            return
        
        # Inspect packet content for advanced threat detection
        if not inspect_packet(packet):
            return
        
        # Log allowed packets
        log_allowed_packet(src_ip, dst_ip)
        print(f"Allowed: {src_ip} -> {dst_ip}")

# Start sniffing packets on loopback interface
print("Firewall is running...")
sniff(filter="ip", prn=packet_handler, store=0, iface="lo0")
