#!/usr/bin/python

import socket
import os
from optparse import OptionParser

HELP = """\
Sniff socket sniffer read a single package and prints it out.
"""

def parse_options():    
    parser = OptionParser(usage='usage: %prog [options] <remote-ip>',
                          version='%prog 1.0', description=HELP)
    parser.add_option('-p', '--remote-port', action='store', type='int', dest='port',
                      default=0,
                      help='port on server to listen on')
    
    options, args = parser.parse_args()

    if len(args) != 1:
        parser.error('Incorrect number of arguments.')
    
    return options, args[0]


def main():
    options, remote = parse_options()
    
    if os.name == "nt":
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP
    
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    
    sniffer.bind((remote, options.port))
    
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    print ('Sniffing package from %s:%d' % (remote, options.port))
    #read singel package
    print sniffer.recvfrom(655565)
    
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    
    
    
    
if __name__ == '__main__':
    main()