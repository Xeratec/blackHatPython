#!/usr/bin/python

import socket
import struct
import os
from ctypes import *
from optparse import OptionParser

HELP = """\
Sniffer reads a single package decodes the IP Layer and prints it out.
"""

g_verbose = True

class IP(Structure):
    _fields_= [
        ("ihl",     c_ubyte,4),
        ("version", c_ubyte,4),
        ("tos",     c_ubyte),
        ("len",     c_ushort),
        ("id",      c_ushort),
        ("offset",  c_ushort),
        ("ttl",     c_ubyte),
        ("protocol_num", c_ubyte),
        ("sum",     c_ushort),
        ("src",     c_ulong),
        ("dst",     c_ulong)       
    ]
    
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)
    
    def __init__(self, socket_buffer = None):
        # map protocol constats to their names
        self.protocol_map = {1:"ICMP", 6:"TCP", 17: "UDP"}
        
        # human readable IP addresses
        self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
        self.dest_address = socket.inet_ntoa(struct.pack("<L", self.dst))
        
        # humen readable protocol
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)
            
class ICMP(Structure):
    _fields_ = [
        ("type",    c_ubyte),
        ("code",    c_ubyte),
        ("checksum",c_ushort),
        ("unused",  c_ushort),
        ("next_hop_mtu,", c_ushort)
    ]
    
    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)
    
    def __init__ (self, socket_buffer):
        pass
    

def parse_options():   
    
    global g_verbose     
    parser = OptionParser(usage='usage: %prog [options] <remote-ip>',
                          version='%prog 1.0', description=HELP)
    parser.add_option('-q', '--quiet', action='store_false', dest='verbose', default=True,
                      help='squelch all informational output')
    parser.add_option('-p', '--remote-port', action='store', type='int', dest='port',
                      default=0,
                      help='port on server to listen on')
    
    options, args = parser.parse_args()

    if len(args) != 1:
        parser.error('Incorrect number of arguments.')
    g_verbose = options.verbose
    
    return options, args[0]

def verbose(s):
    if g_verbose:
        print(s)
        
def main():
    
    options, remote = parse_options()
    
    
    if os.name == "nt":
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP
    
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    verbose ('Bind to  %s:%d' % (remote, options.port))
    
    sniffer.bind((remote, options.port))
    
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    print ('Sniffing package from %s:%d' % (remote, options.port))
    
    #read singel package and decode
    try:
        while True:
            raw_buffer = sniffer.recvfrom(65565)[0]
            ip_header = IP(raw_buffer[0:20])
            print "Protocol: %s %s -> %s" % (ip_header.protocol, ip_header.src_address, ip_header.dest_address)
            
            if ip_header.protocol == "ICMP":
                offset = ip_header.ihl * 4
                buf = raw_buffer[offset:offset+sizeof(ICMP)]
                
                icmp_header = ICMP(buf)
                
                print "ICMP -> Type: %d Code: %d" % (icmp_header.type, icmp_header.code)
            
    except KeyboardInterrupt:    
        if os.name == "nt":
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
     
if __name__ == '__main__':
    main()
