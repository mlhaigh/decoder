#!/usr/bin/env python

import sys
import logging
logging.getLogger('scapy').setLevel(1)
from scapy.all import *
import zlib
import binascii
import hashlib
from Crypto.Cipher import DES

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
pcount = 0

for p in pcap:
    pcount = pcount + 1
    if p[IP].src == '169.254.118.2':
        print "******PACKET %d FROM SERVER TO CLIENT******" % pcount
    elif p[IP].src == '169.254.118.0':
        print "******PACKET %d FROM CLIENT TO SERVER******" % pcount
    if p[TCP].payload:
        data = str(p[TCP].payload)
        if data[0:4] == 'peep':
            print data[8]
            if data[8] == 'q':
                pass
                print "BRANCH71"
                print zlib.decompress(data[16:])
            elif data[8] == 'r':
                pass
                print "BRANCH72"
		data_out = []
		for bytes in arr:
		    #print(hex(bytes))
		    #data_out.append(crypto[bytes])
		data_str = ''
		data_str = data_str.join(data_out)
		print(data_str)
            elif data[8] == 's':
                pass
                print "BRANCH73"
                hexdump(data)
            elif data[8] == 't':
                print "BRANCH74"
                hexdump(data)
                hash = hashlib.md5()
                hash.update(data[:16])
                des = DES.new(hash.digest()[:8], DES.MODE_ECB)
                print data[4]
                len = ord(data[4])
                print len
                len = len - 28
                print len
                des.decrypt(data[16:len])
                print data
            else:
                print "UNKNOWN PACKET TYPE"
                p.show()
    print "******END PACKET %d******\n" % pcount


f_in.close()

