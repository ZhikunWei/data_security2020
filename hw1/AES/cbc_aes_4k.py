#!/usr/bin/python 
# -*-coding:utf-8 -*-
__author__ = '99K'
import numpy as np

from single_group import aes_encode, aes_decode, extendKey

if __name__ == '__main__':
    plaintext = []
    ciphertext = []
    IV = np.zeros(16, dtype=int)
    for i in range(32):
        plaintext.append(np.random.randint(0, 256, size=16))
    
    key = np.random.randint(0, 256, size=16)
    round_keys = extendKey(key)
    print('plaintext', plaintext)
    
    C_pre = IV
    for i in range(len(plaintext)):
        Ci = aes_encode(C_pre ^ plaintext[i], round_keys)
        ciphertext.append(Ci)
        C_pre = Ci
    print('ciphertext', ciphertext)
    
    decode_text = []
    C_pre = IV
    for i in range(len(ciphertext)):
        Pi = aes_decode(ciphertext[i], round_keys) ^ C_pre
        decode_text.append(Pi)
        C_pre = ciphertext[i]
    print('decodetext', decode_text)
    
    print('plaintext - decode_text:',
          [x-y for x, y in zip(plaintext, decode_text)])
    print('diff between plaintext and decoded text:',
          sum([sum(x - y) for x, y in zip(plaintext, decode_text)]))