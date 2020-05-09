#!/usr/bin/python 
# -*-coding:utf-8 -*-
__author__ = '99K'

import random
import time

k = (0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
     0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
     0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
     0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
     0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
     0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
     0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
     0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
     0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
     0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
     0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
     0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
     0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
     0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
     0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
     0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2)


def rotr(x, y):
    return ((x >> y) | (x << (32 - y))) & 0xFFFFFFFF


def messagePad(message):
    len_bits = len(message) * 4
    k = 7
    while True:
        if (len_bits + 1 + k) % 512 == 448:
            break
        else:
            k += 4
    
    padmsg = message + '80'
    for i in range((k - 7) // 4):
        padmsg += '0'
    padmsg += '%016X' % len_bits
    
    return padmsg


def dec2hex(dec):
    return hex(dec)[2:]


def dec2bin(dec):
    return bin(dec)[2:].zfill(64)


def hex2bin(hex):
    dec = int(hex, 16)
    return bin(dec)[2:].zfill(64)


def chunks(messageLength, chunkSize):
    chunkValues = []
    for i in range(0, len(messageLength), chunkSize):
        chunkValues.append(messageLength[i:i + chunkSize])
    return chunkValues


def sha256(msg):
    chunk = chunks(msg, 256)
    h = (0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
         0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)
    h0, h1, h2, h3, h4, h5, h6, h7 = h
    for word in chunk:
        w = [0] * 64
        for i in range(16):
            w[i] = int(word[i], 2)
        for i in range(16, 64):
            s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF
        a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7
        for i in range(64):
            s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = s0 + maj
            s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
            ch = (e & f) ^ ((~e) & g)
            t1 = h + s1 + ch + k[i] + w[i]
            
            h = g
            g = f
            f = e
            e = (d + t1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xFFFFFFFF
        
        h0 = h0 + a & 0xffffffff
        h1 = h1 + b & 0xffffffff
        h2 = h2 + c & 0xffffffff
        h3 = h3 + d & 0xffffffff
        h4 = h4 + e & 0xffffffff
        h5 = h5 + d & 0xffffffff
        h6 = h6 + e & 0xffffffff
        h7 = h7 + d & 0xffffffff
    return '%08x%08x%08x%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4, h5, h6, h7)


if __name__ == '__main__':
    msg = ''
    bitNum = 0
    for i in range(2000):
        tmp = dec2hex(random.randint(0, 2 ** 512 - 1))
        bitNum += len(tmp) * 4
        msg += tmp
    print('msg length(bits):', bitNum)
    msg = messagePad(msg)
    print('msg bit length after padding', len(msg) * 4)
    msg = hex2bin(msg)
    
    start = time.process_time()
    hashvalue = sha256(msg)
    finish = time.process_time()
    t = finish - start
    print('hash time', t, 'speed ', len(msg) // t, 'bit/s')
    print('hash value', hashvalue)
