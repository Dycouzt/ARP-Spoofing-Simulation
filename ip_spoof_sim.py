from scapy.all import *

def spoof_icmp_reply(packet):
    # Ensure it's an ICMP Echo Request (ping)
    if packet.haslayer(ICMP) and packet[ICMP].type == 8:
        print(f"[+] Sniffed ICMP Echo Request from {packet[IP].src} to {packet[IP].dst}")

        # Create the spoofed ICMP Echo Reply
        spoofed_packet = IP(
            src=packet[IP].dst,  # Swap src and dst to spoof a reply
            dst=packet[IP].src
        ) / ICMP(
            type=0,  # Echo Reply
            id=packet[ICMP].id,
            seq=packet[ICMP].seq
        ) / packet[Raw].load  # Include original payload

        # Send the spoofed packet
        send(spoofed_packet, verbose=False)
        print(f"[+] Sent spoofed ICMP Echo Reply to {packet[IP].src}")

# Start sniffing ICMP traffic
print("[*] Sniffing ICMP packets...")
sniff(filter="icmp", prn=spoof_icmp_reply, store=0)