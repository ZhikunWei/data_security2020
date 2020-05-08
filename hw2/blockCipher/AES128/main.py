#!/usr/bin/python 
# -*-coding:utf-8 -*-
__author__ = '99K'
import numpy as np
import time

from single_group import aes_encode, aes_decode, extendKey

if __name__ == '__main__':
    plaintext = []
    ciphertext = []
    IV = np.random.randint(0, 256, size=16, dtype=int)
    for i in range(8000):
        plaintext.append(np.random.randint(0, 256, size=16))
    bitNum = 128*8000
    key = np.random.randint(0, 256, size=16)
    round_keys = extendKey(key)
    
    print('plaintext size', bitNum)
    
    startEnc = time.process_time()
    C_pre = IV
    for i in range(len(plaintext)):
        Ci = aes_encode(C_pre ^ plaintext[i], round_keys)
        ciphertext.append(Ci)
        C_pre = Ci
    finishEnc = time.process_time()
    t = finishEnc-startEnc
    print('encode cost time:', t, 's, encode speed:', bitNum//t, 'bit/s')
    
    decode_text = []
    C_pre = IV
    for i in range(len(ciphertext)):
        Pi = aes_decode(ciphertext[i], round_keys) ^ C_pre
        decode_text.append(Pi)
        C_pre = ciphertext[i]
    finishDec = time.process_time()
    t = finishDec-finishEnc
    print('decode cost time:', t, 's, encode speed:', bitNum//t, 'bit/s')
    
    