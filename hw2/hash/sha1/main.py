#!/usr/bin/python 
# -*-coding:utf-8 -*-
__author__ = '99K'

import random
import time


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


def chunks(messageLength, chunkSize):
    chunkValues = []
    for i in range(0, len(messageLength), chunkSize):
        chunkValues.append(messageLength[i:i + chunkSize])
    return chunkValues


def leftRotate(chunk, rotateLength):
    return ((chunk << rotateLength) | (chunk >> (32 - rotateLength))) & 0xffffffff


def sha1(v, msg):
    chunk = chunks(msg, 512)
    h0, h1, h2, h3, h4 = v
    for eachChunk in chunk:
        words = chunks(eachChunk, 32)
        
        w = [0] * 80
        for n in range(0, 16):
            w[n] = int(words[n], 2)
        
        for i in range(16, 80):
            w[i] = leftRotate((w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]), 1)
        
        a, b, c, d, e = h0, h1, h2, h3, h4
        # main loop:
        for i in range(0, 80):
            if 0 <= i <= 19:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            
            elif 60 <= i <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6
            
            a, b, c, d, e = ((leftRotate(a, 5) + f + e + k + w[i]) & 0xffffffff, a, leftRotate(b, 30), c, d)
        h0 = h0 + a & 0xffffffff
        h1 = h1 + b & 0xffffffff
        h2 = h2 + c & 0xffffffff
        h3 = h3 + d & 0xffffffff
        h4 = h4 + e & 0xffffffff
    
    return '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)


def dec2bin(dec):
    return bin(dec)[2:].zfill(64)


def hex2bin(hex):
    dec = int(hex, 16)
    return bin(dec)[2:].zfill(64)


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
    
    v = (0x67452301, 0xefcdab89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)
    start = time.process_time()
    hashvalue = sha1(v, msg)
    finish = time.process_time()
    t = finish - start
    print('hash time', t, 'speed ', len(msg) // t, 'bit/s')
    print('hash value', hashvalue)
