#!/usr/bin/env python
# -*- coding: utf-8 -*-

# make 2/1 = 0.5, instead of 0
from __future__ import division

""" sha512t.py generate truncated hashes SHA-512/t with t=1..511 """

__author__      = "Otto Dietz"
__email__       = "otto.dietz@physik.hu-berlin.de"


from time import time
from ctypes import *
from collections import Counter
import numpy as np

# REFERENCE IVs for SHA512 and SHA512/t from FIPS-180 
SHA512_REF_IV = [0x6a09e667f3bcc908,
                0xbb67ae8584caa73b,
                0x3c6ef372fe94f82b,
                0xa54ff53a5f1d36f1,
                0x510e527fade682d1,
                0x9b05688c2b3e6c1f,
                0x1f83d9abfb41bd6b,
                0x5be0cd19137e2179]

SHA512t224_REF_IV=[ 0x8C3D37C819544DA2,
                    0x73E1996689DCD4D6,
                    0x1DFAB7AE32FF9C82,
                    0x679DD514582F9FCF,
                    0x0F6D2B697BD44DA8,
                    0x77E36F7304C48942,
                    0x3F9D85A86A1D36C8,
                    0x1112E6AD91D692A1]

SHA512t256_REF_IV=[ 0x22312194FC2BF72C,
                    0x9F555FA3C84C64C2,
                    0x2393B86B6F53B151,
                    0x963877195940EABD,
                    0x96283EE2A88EFFE3,
                    0xBE5E1E2553863992,
                    0x2B0199FC2C85B8AA,
                    0x0EB72DDC81C52CA2]

def charstr2long(charstr):
    return long("".join("{:02x}".format(ord(c)) for c in charstr),16)

def hexstr2long(hexstr):
    return long(hexstr,16)

def SHA512iv(msg,iv):
    global lib
    c_iv = (c_longlong * len(iv))(*iv) # * expands ([1,2,3]) to (1,2,3)
    hash = "\0"*64
    phash = c_char_p(hash)
    lib.SHA512iv(c_char_p(msg),len(msg),c_char_p(hash),c_iv)
    return hash


#SHA-512/t IV Generation Function
def SHA512_gen_IV(t):
    global SHA512_REF_IV

    t = int(t)
    assert ( t<512 and t>0 and 384 != t ), "wrong t value." 

    # generate temporary IV from SHA512_REF_IV
    iv = SHA512_REF_IV
    iv = [h ^ 0xa5a5a5a5a5a5a5a5 for h in iv] # XOR
    
    # hash sha_str with temporary IV
    sha_str = "SHA-512/" + str(t)
    hash = SHA512iv(sha_str,iv)

    # generated hash contains new IV, extract it
    new_iv = [ hash[8*i:8*(i+1)] for i in range(8) ]
    new_iv = [int("".join("{:02x}".format(ord(c)) for c in i),16) for i in new_iv]
    return new_iv

def SHA512t(msg,t):
    iv = SHA512_gen_IV(t)
    #print "Generating SHA512/"+str(t)
    lhash = SHA512iv(msg,iv)
    lhash = lhash[0:int(t/8)]
    lhash  = charstr2long(lhash)
    return lhash


def SHA512t48(msg):
    global iv48
    #print "Generating SHA512/"+str(t)
    lhash = SHA512iv(msg,iv48)
    lhash = lhash[0:6]
    lhash  = charstr2long(lhash)
    return lhash




def print_hex(hash):
    print " ".join("{:02x}".format(ord(c)) for c in hash)

#
# New implementation of SHA512 with custom IV, adapted from openssl
#
lib = cdll.LoadLibrary("./sha512iv.so") 
iv48 = SHA512_gen_IV(48)


print """
#
# Compare new SHA512iv with old SHA512
# """

s = r"test input string"
ps = c_char_p(s)

hash = "\0"*64
phash = c_char_p(hash)
n = c_int(len(s))
iv = (c_longlong * 8)(*SHA512_REF_IV) 

print "Original function"
lib.SHA512(ps,n,phash)
print_hex(hash)

orighash = hash

print "New function with same IV"
lib.SHA512iv(ps,n,phash,byref(iv))
print_hex(hash)

assert orighash == hash, "Error: New implemntation differs from old one!"
assert SHA512_gen_IV(224) == SHA512t224_REF_IV, "Reference IV for t=224 differs from generated one!"
assert SHA512_gen_IV(256) == SHA512t256_REF_IV, "Reference IV for t=224 differs from generated one!"
print "### TEST OKAY ###"

print """
#
# Check given test vectors
# """
testvec     = {    '40':(8,'000000'),
                    'e6' :  ( 8,'123456'),
                    '1c' :  ( 8,'uvwxyz'),
                    '1893' :  ( 16,'000000'),
                    'ed51' :  ( 16,'123456'),
                    'd4f3' :  ( 16,'uvwxyz'),
                    'c36145' :  ( 24,'000000'),
                    '322e02' :  ( 24,'123456'),
                    'b82f96' :  ( 24,'uvwxyz'),
                    '0fb87900' :  ( 32,'000000'),
                    'b01b3f58' :  ( 32,'123456'),
                    'a7802f1c' :  ( 32,'uvwxyz'),
                    '41561e6db1' :  ( 40,'000000'),
                    '6d92e23336' :  ( 40,'123456'),
                    '12807bfe4b' :  ( 40,'uvwxyz'),
                    'e71453add8ee' :  ( 48,'000000'),
                    '38ebd7973918' :  ( 48,'123456'),
                    'd444c346a738' :  ( 48,'uvwxyz'),
                    '34acd645778a15' :  ( 56,'000000'),
                    'b49acfda08675b' :  ( 56,'123456'),
                    '350690fa30f57b' :  ( 56,'uvwxyz'),
                    '0c8beffa2e95addd' :  ( 64,'000000'),
                    '52261eacb45fe456' :  ( 64,'123456'),
                    'ecfacd8d22e401c6' :  ( 64,'uvwxyz'),
                    '857a80e7286803cf57' :  ( 72,'000000'),
                    '2dc46cba92f277e7ee' :  ( 72,'123456'),
                    '804886d65bb10ba6b9' :  ( 72,'uvwxyz'),
                    '21fb1ba1eb71f834d109' :  ( 80,'000000'),
                    'eeb1e73ed321fb324774' :  ( 80,'123456'),
                    '008184950f9c830e7fdc' :  ( 80,'uvwxyz'),
                    'e382856f8019363544df4e' :  ( 88,'000000'),
                    '0689adfdb5dc251ebee870' :  ( 88,'123456'),
                    '298eaa31c4ecf5f5963d09' :  ( 88,'uvwxyz'),
                    '189135861b522f62756400b2' :  ( 96,'000000'),
                    '7faeba0512326c125ddc89f7' :  ( 96,'123456'),
                    '555e97a5903df06d2f818a19' :  ( 96,'uvwxyz'),
                    'b7a5c6dbfad0d3c9d77560b9ea' :  ( 104,'000000'),
                    '7fa9d643798cb0605eb8b07311' :  ( 104,'123456'),
                    'a3d0a1dce670fe231c80a2fbfb' :  ( 104,'uvwxyz'),
                    'b61089a3983050f4fbf8687d6fbf' :  ( 112,'000000'),
                    'c415857e3a4d15cac1439003f386' :  ( 112,'123456'),
                    '36f690af14514051741107661876' :  ( 112,'uvwxyz'),
                    '44e707b93fd9187f8d9a80feb80e23' :  ( 120,'000000') }

for hash, pair in testvec.iteritems():
    bits, msg = pair
    hash = long(hash,16)
    calchash = SHA512t(msg,bits)
    assert calchash == hash, "test vectors do not match!"
    print "checking done for t=", bits, msg

print "### TEST OKAY ###"
