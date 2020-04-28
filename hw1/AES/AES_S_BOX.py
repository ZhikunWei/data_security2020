#!/usr/bin/python 
# -*-coding:utf-8 -*-
__author__ = '99K'

import numpy as np


def gcd(a, b):
    if a < b:
        a, b = b, a
    while b:
        tmp = a
        a = b
        b = tmp % b
    return a


def multiplicative_inverse(a, b):
    d = gcd(a, b)
    if d != 1 and d != -1:
        return -1
    r0, r1 = a, b
    x0, y0 = 1, 0
    x1, y1 = 0, 1
    if b == 1 or b == -1:
        y2 = y1
    while r1 != 1 and r1 != -1:
        q1 = r0 // r1
        r2 = r0 % r1
        x2 = x0 - q1 * x1
        y2 = y0 - q1 * y1
        r0, r1 = r1, r2
        x0, x1 = x1, x2
        y0, y1 = y1, y2
    if y2 < 0:
        y2 = a + y2
    return y2


def polynomialMutil(a, b):
    tmp = []
    for i in range(8):
        tmp.append((a << i) * ((b >> i) & 0x1))
    res = tmp[0] ^ tmp[1] ^ tmp[2] ^ tmp[3] ^ tmp[4] ^ tmp[5] ^ tmp[6] ^ tmp[7]
    return res


def findHighBit(x):
    i = 0
    while x:
        i += 1
        x = x >> 1
    return i


def polynomialDiv(a, b):
    r0, qn = a, 0
    bit_cnt = findHighBit(r0) - findHighBit(b)
    while bit_cnt >= 0:
        qn = qn | (1 << bit_cnt)
        r0 = r0 ^ (b << bit_cnt)
        bit_cnt = findHighBit(r0) - findHighBit(b)
    return qn, r0


def extendEuclidPolynomial(a, m):
    r0, r1 = m, a
    v0, v1 = 1, 0
    w0, w1 = 0, 1
    while r1 != 1:
        qn, r2 = polynomialDiv(r0, r1)
        v2 = v0 ^ polynomialMutil(qn, v1)
        w2 = w0 ^ polynomialMutil(qn, w1)
        r0, r1 = r1, r2
        v0, v1 = v1, v2
        w0, w1 = w1, w2
    return w1


def byteTransform(a, x):
    res = 0
    for i in range(8):
        res += (((a >> i) & 0x1) ^ ((a >> ((i + 4) % 8)) & 0x1) ^ ((a >> ((i + 5) % 8)) & 0x1) ^ (
                (a >> ((i + 6) % 8)) & 0x1) ^ ((a >> ((i + 7) % 8)) & 0x1) ^ ((x >> i) & 0x1)) << i
    return res


def invByteTransform(a, x):
    res = 0
    for i in range(8):
        res += (((a >> ((i + 2) % 8)) & 0x1) ^ ((a >> ((i + 5) % 8)) & 0x1) ^ ((a >> ((i + 7) % 8)) & 0x1) ^ (
                (x >> i) & 0x1)) << i
    return res


def generate_s_bos(show_mid=False):
    s_box_arr = np.zeros((16, 16), dtype=int)
    
    for i in range(16):
        for j in range(16):
            s_box_arr[i][j] = i * 16 + j  # ((i << 4) & 0xF0) + (j & 0xF)
    if show_mid:
        print("\r\n\rstart\n    0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F", end='')
        for i in range(16):
            print('\r\n%2x ' % i, end='')
            for j in range(16):
                print('%2x ' % (s_box_arr[i][j]), end='')
    
    for i in range(0x10):
        for j in range(0x10):
            if s_box_arr[i][j] != 0:
                s_box_arr[i][j] = extendEuclidPolynomial(s_box_arr[i][j], 0x11B)
    if show_mid:

        print("\r\n\rmid\n    0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F", end='')
        for i in range(0x10):
            print('\r\n%2x ' % i, end='')
            for j in range(0x10):
                print("%2x " % s_box_arr[i][j], end='')
    
    for i in range(0x10):
        for j in range(0x10):
            s_box_arr[i][j] = byteTransform(s_box_arr[i][j], 0x63)
    
    if show_mid:

        print("\r\n\rS BOX\n    0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F", end='')
        for i in range(0x10):
            print('\r\n%2x ' % i, end='')
            for j in range(0x10):
                print("%2x " % s_box_arr[i][j], end='')
    return s_box_arr


def generate_inv_s_box(show_mid=False):
    s_box = np.zeros((16, 16), dtype=int)
    for i in range(16):
        for j in range(16):
            s_box[i][j] = i * 16 + j
    if show_mid:
        print("\r\n\rstart\n    0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F", end='')
        for i in range(0x10):
            print('\r\n%2x ' % i, end='')
            for j in range(0x10):
                print("%2x " % s_box[i][j], end='')
    
    for i in range(16):
        for j in range(16):
            s_box[i][j] = invByteTransform(s_box[i][j], 0x05)
    if show_mid:
        print("\r\n\rmid\n    0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F", end='')
        for i in range(0x10):
            print('\r\n%2x ' % i, end='')
            for j in range(0x10):
                print("%2x " % s_box[i][j], end='')
    
    for i in range(16):
        for j in range(16):
            if s_box[i][j] != 0:
                s_box[i][j] = extendEuclidPolynomial(s_box[i][j], 0x11B)
    if show_mid:
        print("\r\n\rINV S BOX\n    0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F", end='')
        for i in range(0x10):
            print('\r\n%2x ' % i, end='')
            for j in range(0x10):
                print("%2x " % s_box[i][j], end='')
    return s_box


if __name__ == '__main__':
    s_box = generate_s_bos(show_mid=True)
    inv_s_box = generate_inv_s_box(show_mid=True)
