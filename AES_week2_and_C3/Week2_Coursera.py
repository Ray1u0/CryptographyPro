# -*- coding: utf-8 -*-

from Crypto.Cipher import AES
from Crypto import Random
import binascii

#key 128bits 16bytes
CBC_key = '140b41b22a29beb4061bda66b6747e14'

cipher1 = '4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81'
cipher2 = '5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253'

CTR_key = '36f18357be4dbd77f050515c73fcf9f2'

cipher3 = '69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329'
cipher4 = '770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451'

BlockSize = 16 #16 bytes encryption

BS = BlockSize

def str2hexs(strings):
    return binascii.a2b_hex(bytes(strings,'utf-8'))

def strxor(a,b):
    """ xor two hex_bytes of different lengths """
    if len(a) > len(b):
        return "".join([chr(x^y) for (x,y) in zip(a[:len(b)], b)])
    else:
        return "".join([chr(x^y) for (x,y) in zip(a, b[:len(a)])])

def en_strxor(a,b):
    if len(a) > len(b):
        return bytes([x^y for (x,y) in zip(a[:len(b)], b)])
    else:
        return bytes([x^y for (x,y) in zip(a, b[:len(a)])])

def iv_counter(iv):
    iv_len = len(iv)
    iv_plus = iv[iv_len-1]+1
    if iv_plus < 256:
        return iv[:iv_len-1]+bytes([iv_plus])
    else:
        return iv_counter(iv[:iv_len-1])+bytes([0])

def en_CBC_AES(key,plaintext):
    key = str2hexs(key)
    plaintext = bytes(plaintext,'utf-8')    
    #print(plaintext)
    pad = BS - len(plaintext) % BS
    for i in range(pad):
        plaintext += bytes([pad])
    #print('flag')
    cipher = AES.new(key, AES.MODE_ECB)
    iv = Random.new().read(BS)
    #print(iv)
    result = iv
    for i in range(int(len(plaintext)/BS)):
        #print('flag')
        ciphertext = cipher.encrypt(en_strxor(plaintext[i*BS:(i+1)*BS],iv))
        #print(ciphertext)
        iv = ciphertext
        result += ciphertext
    return binascii.b2a_hex(result)

def en_CTR_AES(key,plaintext):
    key = str2hexs(key)
    plaintext = bytes(plaintext,'utf-8') 
    cipher = AES.new(key, AES.MODE_ECB)  
    iv = Random.new().read(BS)  
    result = iv  
    for i in range(int(len(plaintext)/BS)):  
        iv_en = cipher.encrypt(iv)  
        ciphertext = en_strxor(plaintext[i*BS:(i+1)*BS],iv_en)  
        iv = iv_counter(iv)  
        result += ciphertext  
    if len(plaintext) % BS == 0:  
        return result  
    else:  
        iv_en = cipher.encrypt(iv)  
        ciphertext = en_strxor(plaintext[int(len(plaintext)/BS)*BS:],iv_en)  
        result += ciphertext
        return binascii.b2a_hex(result)

def de_CBC_AES(key,ciphertext):
    """ Decryption of AES in CBC mode """
    key = str2hexs(key)
    ciphertext = str2hexs(ciphertext)
    cipher = AES.new(key,AES.MODE_ECB)
    iv = ciphertext[:BS] 
    """ iv放在密文前面 """
    #print(iv)
    result = ''
    for i in range(1,int(len(ciphertext)/BS)):
        message = strxor(cipher.decrypt(ciphertext[i*BS:(i+1)*BS]),iv)
        iv = ciphertext[i*BS:(i+1)*BS]
        result += message
    pad = len(result)
    #print(result)
    """ 若需填充n字节，则填充n个n(16进制) """
    return result[:pad-ord(result[pad-1])]

def de_CTR_AES(key,ciphertext):
    """ Dcryption of AES in CTR mode """
    key = str2hexs(key)
    ciphertext = str2hexs(ciphertext)
    cipher = AES.new(key,AES.MODE_ECB)
    iv = ciphertext[:BS]
    result = ''
    for i in range(1,int(len(ciphertext)/BS)):
        iv_en = cipher.encrypt(iv)
        message = strxor(ciphertext[i*BS:(i+1)*BS],iv_en)
        iv = iv_counter(iv)
        result += message
    if len(ciphertext) % BS == 0:
        return result
    else:
        iv_en = cipher.encrypt(iv)
        message = strxor(ciphertext[int(len(ciphertext)/BS)*BS:],iv_en)
        iv = iv_counter(iv)
        result += message
        return result
    
    
message1 = de_CBC_AES(CBC_key, cipher1)
message2 = de_CBC_AES(CBC_key, cipher2)
message3 = de_CTR_AES(CTR_key, cipher3)
message4 = de_CTR_AES(CTR_key, cipher4)
print('Question 1:{}\nQuestion 2:{}\nQuestion 3:{}\nQuestion 4:{}\n'.format(message1,message2,message3,message4))

c1 = en_CBC_AES(CBC_key,message1)
c3 = en_CTR_AES(CTR_key,message3)