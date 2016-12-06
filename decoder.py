#!/usr/bin/env python

import sys
import logging
logging.getLogger('scapy').setLevel(1)
from scapy.all import *
import zlib
import binascii
import hashlib

usage = ("usage: %s <filename>") % sys.argv[0]

if len(sys.argv) < 2:
    print usage
    exit(1)

pcap = rdpcap(sys.argv[1])
print pcap
arr = bytearray([0x0F, 0xB0, 0x0F, 0x50, 0x22, 0xDC, 0xDC, 0xDC, 0x33, 0x0F, 0x93, 0x2B, 0x95])
name =  "TotallyL_72.mem"
f_in = open(name, "rb")
crypto = f_in.read(256)

for p in pcap:
    if p[IP].src == '169.254.118.2':
        print "***PACKET FROM SERVER TO CLIENT***"
    elif p[IP].src == '169.254.118.0':
        print "***PACKET FROM CLIENT TO SERVER***"
    if p[TCP].payload:
        data = str(p[TCP].payload)
        if data[0:4] == 'peep':
            print data[8]
            if data[8] == 'q':
                print "BRANCH71"
                print zlib.decompress(data[16:])
            elif data[8] == 'r':
                print "BRANCH72"
		data_out = []
		for bytes in arr:
		    #print(hex(bytes))
		    data_out.append(crypto[bytes])
		data_str = ''
		data_str = data_str.join(data_out)
		print(data_str)
            elif data[8] == 's':
                print "BRANCH73"
                hexdump(data)
            elif data[8] == 't':
                print "BRANCH74"
                hexdump(data)
            else:
                print "UNKNOWN PACKET TYPE"
                p.show()


f_in.close()

