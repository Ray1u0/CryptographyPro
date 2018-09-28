# -*- coding: utf-8 -*-

import base64
import binascii
#Challenge 1
s1='49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
s2='SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

hex_bytes=bytes.fromhex(s1)
result1=base64.b64encode(hex_bytes)
print(result1)

#Challenge 2
s3='1c0111001f010100061a024b53535009181c'
s4='686974207468652062756c6c277320657965'

hex_s3=bytes.fromhex(s3)
hex_s4=bytes.fromhex(s4)

result2 = b''
for i in range(len(hex_s3)):
    result2 += bytes([hex_s3[i]^hex_s4[i]])

result2 = binascii.b2a_hex(result2)
print(result2)

