# 6.19
"""
 Program: Scapy open port scanner
 Author: Tomer Shaar
 Description: A port scanner that checks if a port is open and connected to a certain ip
 Date: 23/03/2026
"""
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr1, send

START_PORT = 20
END_PORT = 1024
TIMEOUT = 0.5


def is_port_open(dst_ip, port):
    syn_packet = IP(dst=dst_ip) / TCP(dport=port, flags="S")
    response = sr1(syn_packet, timeout=TIMEOUT, verbose=0)

    if response is None:
        return False

    if not response.haslayer(TCP):
        return False

    tcp_layer = response.getlayer(TCP)

    if tcp_layer.flags == 0x12:   # SYN+ACK
        rst_packet = IP(dst=dst_ip) / TCP(dport=port, flags="R")
        send(rst_packet, verbose=0)
        return True

    return False


def main():
    dst_ip = input("Enter destination IP: ").strip()

    print(f"\nScanning {dst_ip}...")
    print("Open ports:")

    found_open = False

    for port in range(START_PORT, END_PORT + 1):
        if is_port_open(dst_ip, port):
            print(port)
            found_open = True

    if not found_open:
        print("No open ports found in range 20-1024.")


if __name__ == "__main__":
    main()
