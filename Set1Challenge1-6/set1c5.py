# -*- coding: utf-8 -*-

def repeating_key_xor(m,key):
    result=b''
    k=0
    for i in m:
        result+=bytes([i^key[k%len(key)]])
        k+=1
    return result

    
if __name__ == '__main__':
    m="Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    key="ICE"
    m=bytes(m,'utf-8')
    key=bytes(key,'utf-8')
    c=repeating_key_xor(m,key)
    print(c.hex())