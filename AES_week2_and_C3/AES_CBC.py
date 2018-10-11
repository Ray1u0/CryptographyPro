# -*- coding: utf-8 -*-

from hashlib import md5
from base64 import b64encode
from base64 import b64decode
from Crypto import Random
from Crypto.Cipher import AES


BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) *\
                chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]


class AESCipher:
    """
    Usage:
        c = AESCipher('password').encrypt('message')
        m = AESCipher('password').decrypt(c)
    """

    def __init__(self, key):
        self.key = md5(key.encode('utf8')).hexdigest()

    def encrypt(self, raw):
        raw = pad(raw)
        iv = Random.new().read(AES.block_size)
        k = self.key
        k = bytes(k,'utf-8')
        
        raw = bytes(raw,'utf-8')
        cipher = AES.new(k, AES.MODE_CBC, iv)
        return b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = b64decode(enc)
        iv = enc[:16]
        k = bytes(self.key,'utf-8')
        cipher = AES.new(k, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(enc[16:])).decode('utf8')
    
    def usage():
        s1 = 'Usage:'
        s2 = "c = AESCipher('password').encrypt('message')"
        s3 = "m = AESCipher('password').decrypt(c)"
        print('\n{}\n    {}\n    {}\n'.format(s1, s2, s3))
        return True

        
        """
        msg = input('Message...: ')
        pwd = input('Password..: ')
        """


if __name__ == '__main__':
    msg = 'This a test that I do to learn something about the AES which is CBC mode.'
    pwd = '1234567890123456'
    cpt = AESCipher(pwd).encrypt(msg)

    print('Ciphertext:', cpt, '\n')

    message = AESCipher(pwd).decrypt(cpt)

    print('plaintext:', message)
    
    f = AESCipher.usage()
    

