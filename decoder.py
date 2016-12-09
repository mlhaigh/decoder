#!/usr/bin/env python

import sys
import logging
logging.getLogger('scapy').setLevel(1)
from scapy.all import *
import zlib
import binascii
import hashlib
from Crypto.Cipher import DES

def detect_direction(data):
    return {
        'kcab' : 0,
        'trts' : 0,
        'exec' : 1,
        'exe' : 1,
        'rest' : 1
    }.get(data, 2)

def decode_71(data):
    return zlib.decompress(data[16:])

def decode_72(data):
    data_out = []
    for bytes in data[12:]:
        idx = ord(bytes)
        if crypto[idx] == 254 or \
                crypto[idx] == 166:
            data_out.append(chr(ord(crypto[idx])))
        else:
            data_out.append(chr(ord(crypto[idx])))
    data_str = ''
    data_str = data_str.join(data_out)
    return data_str

def decode_73(data):
    table = []
    for i in range(256):
        table.append(i)
    table.append(0)
    table.append(0)
    var_1 = 0
    data_list = []    
    for i in range(256):
        mod_counter = i%16
        var_1 = (ord(data[mod_counter+12]) + table[i] + var_1) & 255
        temp = table[var_1]
        table[var_1] = table[i]
        table[i] = temp
    for i in range(ord(data[4])-28):
        table[256] = table[256] + 1
        table[257] = (table[table[256]]+table[257]) & 255
        temp = table[table[257]]
        table[table[257]] = table[table[256]]
        table[table[256]] = temp
        var_1 = (table[table[256]] + table[table[257]]) & 255
        xor =  table[var_1]^ord(data[i+28])
        data_list.append(chr(table[var_1]^ord(data[i+28])))
    data_str = ''
    data_str = data_str.join(data_list)
    return data_str

def decode_74(data):
    pass
   # hexdump(data)
   # hash = hashlib.md5()
   # hash.update(data[12:28])
   # salt = "0x00/0x00"
   # iterations = 4
   # keySize = 8
   # key = hashlib.pbkdf2_hmac('md5', data[12:28], \
   #         salt, iterations, keySize)
   # key = hash.digest()[8:16]
   # des = DES.new(key, DES.MODE_ECB)
   # len = ord(data[4])
   # des.decrypt(data[28:len])
   # print data

usage = ("usage: %s <filename>") % sys.argv[0]

if len(sys.argv) < 2:
    print usage
    exit(1)

pcap = rdpcap(sys.argv[1])
print pcap
pcount = 0
ref_name =  "TotallyL_72.mem"
f_in = open(ref_name, "rb")
crypto = f_in.read(256)
f_in.close()

for p in pcap:
    pcount = pcount + 1
    if p[TCP].payload:
        data = str(p[TCP].payload)
        if detect_direction(data) == 0:
            print "******PACKET %d FROM SERVER TO CLIENT******" % pcount
        elif detect_direction(data) == 1:
            print "******PACKET %d FROM CLIENT TO SERVER******" % pcount
        else:
            print "******PACKET %d OTHER******" % pcount
        if data[0:4] == 'peep':
            if data[8] == 'q':
                print decode_71(data)
            elif data[8] == 'r':
                print decode_72(data)
            elif data[8] == 's':
                print decode_73(data)
            elif data[8] == 't':
                print "74 Packet"
            else:
                print "UNKNOWN PACKET TYPE"
                p.show()
    else:
        print "******PACKET %d NO PAYLOAD******" % pcount
    print "******END PACKET %d******\n" % pcount


f_in.close()

