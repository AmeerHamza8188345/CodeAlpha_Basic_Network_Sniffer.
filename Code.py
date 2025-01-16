from scapy.all import sniff, IP, TCP, UDP


     # This is the function to handle each packet
def analyze_packet(packet):
        # Extract source and destination IP addresses
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
            # Write packet information to log file
        print(f"[+] Packet Captured: {ip_src} -> {ip_dst}")

            # Start packet sniffing 
        if TCP in packet:
            print(f"    Protocol: TCP | Src Port: {packet[TCP].sport} | Dst Port: {packet[TCP].dport}")
        elif UDP in packet:
            print(f"    Protocol: UDP | Src Port: {packet[UDP].sport} | Dst Port: {packet[UDP].dport}")
        else:
            print("    Protocol: Other")

def start_sniffer(interface=None):
    print("[*] Starting network sniffer...")
    sniff(iface=interface, prn=analyze_packet, store=False)

# Check if the script is being run directly
if __name__ == "__main__":
    try:
        start_sniffer(None)  # Use None for all interfaces or specify your network interface
    except KeyboardInterrupt:
        print("\n[*] Stopping sniffer. Exiting...")




from scapy.all import sniff

def packet_callback(packet):
    print(packet.summary())

# Start sniffing on your default network interface
sniff(prn=packet_callback, count=100)
