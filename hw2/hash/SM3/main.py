#!/usr/bin/python 
# -*-coding:utf-8 -*-
__author__ = '99K'

import random
import time

IV = (0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e)
T0_15 = 0x79cc4519
T16_63 = 0x7a879d8a
SM3_MSG_MAX_BITS = 2 << 63


def lrotate(src, bits):
    return ((src << bits) | (src >> abs(32 - bits))) & 0xFFFFFFFF


def Xor(data1, data2):
    return data1 ^ data2


def gcd(a, b):
    while b != 0:
        c = a % b
        a = b
        b = c
    return a


def _ff_0_15(x, y, z):
    return x ^ y ^ z


def _ff_16_63(x, y, z):
    return (x & y) | (x & z) | (y & z)


def _gg_0_15(x, y, z):
    return x ^ y ^ z


def _gg_16_63(x, y, z):
    return (x & y) | ((~x) & z)


def _p0_conv(x):
    return x ^ lrotate(x, 9) ^ lrotate(x, 17)


def _p1_conv(x):
    return x ^ lrotate(x, 15) ^ lrotate(x, 23)


def _sm3_message_pad(message):
    len_bits = len(message) * 4
    k = 7
    while True:
        if (len_bits + 1 + k) % 512 == 448 % 512:
            break
        else:
            k += 8
    padmsg = message + '80'
    out_format = '%%0%dX' % ((k - 7) / 4)
    padmsg += out_format % 0x00
    padmsg += '%016X' % len_bits
    return (padmsg, len(padmsg) * 4)


def dec2hex(dec):
    return hex(dec)[2:]

def msgExtend(msg):
    mlen = len(msg)
    W, WE = [], []
    for i in range(mlen // 8):
        W.append(int(msg[i*8:i*8+8], 16))
    # print(mlen, len(W))
    for i in range(16, 68):
        rspP1 = _p1_conv(W[i - 16] ^ W[i - 9] ^ lrotate(W[i - 3], 15))
        W.append(rspP1 ^ lrotate(W[i - 13], 7) ^ W[i - 6])
    for i in range(0, 64):
        WE.append(W[i] ^ W[i + 4])
    return (W, WE)


def cfProcess(iv, msg):
    W, WE = msgExtend(msg)
    a, b, c, d, e, f, g, h = iv
    for i in range(64):
        if 0 <= i <= 15:
            s1 = lrotate((lrotate(a, 12) + e + lrotate(T0_15, i)) % (2 << 31), 7)
        elif i <= 32:
            s1 = lrotate((lrotate(a, 12) + e + lrotate(T16_63, i))%(2<<31), 7)
        else:
            s1 = lrotate((lrotate(a, 12) + e + lrotate(T16_63, abs(32 - i)))%(2<<31), 7)
        s2 = s1 ^ lrotate(a, 12)
        if 0 <= i <= 15:
            TT1 = (_ff_0_15(a, b, c) + d + s2 + WE[i]) % (2 << 31)
            TT2 = (_gg_0_15(e, f, g) + h + s1 + W[i]) % (2 << 31)
        else:
            if i == 16:
                pass
            TT1 = (_ff_16_63(a, b, c) + d + s2 + WE[i]) % (2 << 31)
            TT2 = (_gg_16_63(e, f, g) + h + s1 + W[i]) % (2 << 31)
        d = c
        c = lrotate(b, 9)
        b = a
        a = TT1
        h = g
        g = lrotate(f, 19)
        f = e
        e = _p0_conv(TT2)
    return (a ^ iv[0], b ^ iv[1], c ^ iv[2], d ^ iv[3], e ^ iv[4], f ^ iv[5], g ^ iv[6], h ^ iv[7])


if __name__ == '__main__':
    plaintext = []
    bitNum = 512 * 2000
    for i in range(2000):
        plaintext.append(dec2hex(random.randint(0, 2 ** 512 - 1)))
        while len(plaintext[i]) < 128:
            plaintext[i] = '0' + plaintext[i]
    v = []
    v.append(IV)
    startHash = time.process_time()
    for i in range(2000):
        v.append(cfProcess(v[i], plaintext[i]))
    finishHash = time.process_time()
    t = finishHash - startHash
    hashValue = '%08X%08X%08X%08X%08X%08X%08X%08X' % (v[len(v) - 1])
    print('hash value:', hashValue)
    print('bit num', bitNum, 'hash cost time:', t, 's,  speed:', bitNum // t, 'bit/s')
    
    
