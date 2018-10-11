# -*- coding: utf-8 -*-

import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Hash import SHA1

p_key = '12345678<8<<<1110182<111116?<<<<<<<<<<<<<<<4'
cipher = '9MgYwmuPrjiecPMx61O6zIuy3MtIXQQ0E59T3xB6u0Gyf1gYs2i3K9Jxaa0zj4gTMazJuApwd6+jdyeI5iGHvhQyDHGVlAuYTgJrbFDrfB22Fpil2NfNnWFBTXyf7SDI'

cipher = binascii.a2b_base64(cipher)

def sha1_hash(c):
    h = SHA1.new()
    h.update(c)
    #print(h)
    return h.hexdigest()

def odd_tran(k):
    p2 = bin(int(k,16))[2:]
    p3 = p2.count('1')
    if p3 % 2 == 0:
        p4 = bytes([int(k,16)^1])
        return p4
    else:
        return binascii.a2b_hex(k)

def a_xor(code):
    k = [7,3,1]
    #print(len(k))
    result = [(ord(code[i])-ord('0'))*k[i%len(k)] for i in range(len(code))]
    result = sum(result)%10
    return result

def de_CBC(key,ciphertext):
    iv = '0'*32
    iv = bytes(iv,'utf-8') 
    iv = binascii.a2b_hex(iv)
    #print(iv)
    cipher = AES.new(key,AES.MODE_CBC,iv)
    pta = cipher.decrypt(ciphertext)
    #pt = unpad(pta,AES.block_size)
    plaintext = pta[:-7]
    return plaintext
        
a = [7,3,1]*2
b = [1,1,1,1,1,6]
t = sum([a[i] * b[i] for i in range(6)]) % 10
print("'?':{}\n".format(t))

mrz = p_key.replace('?',str(t))
mrz_info = mrz[0:10]+mrz[13:20]+mrz[21:28]
mrz_sha1 = sha1_hash(bytes(mrz_info,'utf-8'))

k_seed = mrz_sha1[:32]
c_add = '0'*7 + '1'
p1 = binascii.a2b_hex(c_add)
p2 = binascii.a2b_hex(k_seed) + p1
h_p2 = sha1_hash(p2)
k_enc = h_p2[:int(128/4)]
b = 2
p3 = b''
for i in range(int(len(k_enc)/b)):
    p3 += odd_tran(k_enc[i*b:(i+1)*b])
p3 = binascii.b2a_hex(p3)
print('key_enc:',p3)

key = binascii.a2b_hex(p3)
plaintext = de_CBC(key,cipher)
print('plaintext:',plaintext)

# Cordial Congratulations. They cracked the Nut. The word is: cryptography!

