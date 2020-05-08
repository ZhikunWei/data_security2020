#!/usr/bin/python 
# -*-coding:utf-8 -*-
__author__ = '99K'

import time

import numpy as np
from DES_SBOX import getSBOX

IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

IPinv = [40, 8, 48, 16, 56, 24, 64, 32,
         39, 7, 47, 15, 55, 23, 63, 31,
         38, 6, 46, 14, 54, 22, 62, 30,
         37, 5, 45, 13, 53, 21, 61, 29,
         36, 4, 44, 12, 52, 20, 60, 28,
         35, 3, 43, 11, 51, 19, 59, 27,
         34, 2, 42, 10, 50, 18, 58, 26,
         33, 1, 41, 9, 49, 17, 57, 25]

# 置换选择1  C0表
C0 = [57, 49, 41, 33, 25, 17, 9,
      1, 58, 50, 42, 34, 26, 18,
      10, 2, 59, 51, 43, 35, 27,
      19, 11, 3, 60, 52, 44, 36]

# 置换选择1  D0表
D0 = [63, 55, 47, 39, 31, 23, 15,
      7, 62, 54, 46, 38, 30, 22,
      14, 6, 61, 53, 45, 37, 29,
      21, 13, 5, 28, 20, 12, 4]

# 轮数--左移次数
leftShitRound = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# 置换选择2表
RStable = [14, 17, 11, 24, 1, 5, 3, 28,
           15, 6, 21, 10, 23, 19, 12, 4,
           26, 8, 16, 7, 27, 20, 13, 2,
           41, 52, 31, 37, 47, 55, 30, 40,
           51, 45, 33, 48, 44, 49, 39, 56,
           34, 53, 46, 42, 50, 36, 29, 32]

# 扩充置换表
Ebox = [32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1]

Pbox = [16, 7, 20, 21, 29, 12, 28, 17,
        1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9,
        19, 13, 30, 6, 22, 11, 4, 25]


def leftShit(x):
    return x[1:] + x[0]


def XOR(L, R):
    result = ''
    for i in range(len(L)):
        if ((L[i] == '1') & (R[i] == '1')) | ((L[i] == '0') & (R[i] == '0')):
            result += '0'
        if ((L[i] == '1') & (R[i] == '0')) | ((L[i] == '0') & (R[i] == '1')):
            result += '1'
    return result


def initSubstitution(cleartext):
    result = ''
    for i in range(64):
        result += cleartext[IP[i] - 1]
    L = result[:32]
    R = result[32:]
    return L, R


def invInitSubstitution(binary):
    result = ''
    for i in range(64):
        result += binary[IPinv[i] - 1]
    return result


def replacementSelection1(secretkey):
    C = ''
    D = ''
    for i in range(28):
        C += secretkey[C0[i] - 1]
        D += secretkey[D0[i] - 1]
    return C, D


def replacementSelection2(C, D, round):
    secretKey = ''
    for i in range(round):
        C = leftShit(C)
        D = leftShit(D)
    tmp = C + D
    for i in range(48):
        secretKey += tmp[RStable[i] - 1]
    return C, D, secretKey


def extension(R):
    result = ''
    for i in range(48):
        result += R[Ebox[i] - 1]
    return result


def substitute(binary):
    result = ''
    for i in range(8):
        table = Sbox[i]
        sixBin = binary[6 * i:6 * (i + 1)]
        row = int(sixBin[0] + sixBin[-1], 2)
        column = int(sixBin[1:-1], 2)
        fourBin = table[row][column]
        result += bin(fourBin)[2:].zfill(4)
    return result


# """置换（P）""
def permute(binary):
    result = ''
    for i in range(32):
        result += binary[Pbox[i] - 1]
    return result


# """生成密文"""
def desencode(cleartext, secretKey):
    L, R = initSubstitution(cleartext)
    C, D = replacementSelection1(secretKey)
    for i in range(16):
        C, D, key = replacementSelection2(C, D, leftShitRound[i])
        L, R = R, XOR(L, permute(substitute(XOR(extension(R), key))))
    return invInitSubstitution(R + L)


# """解密"""
def desdecode(ciphertext, secretKey):
    L, R = initSubstitution(ciphertext)
    C, D = replacementSelection1(secretKey)
    keyList = []
    for i in range(16):
        C, D, key = replacementSelection2(C, D, leftShitRound[i])
        keyList.append(key)
    for i in range(16):
        L, R = R, XOR(L, permute(substitute(XOR(extension(R), keyList[15 - i]))))
    return invInitSubstitution(R + L)


# """十进制(int)->二进制(str，64位)"""
def dec2bin(dec):
    return bin(dec)[2:].zfill(64)


# """十六进制(str)->二进制(str,64位)"""
def hex2bin(hex):
    dec = int(hex, 16)
    return bin(dec)[2:].zfill(64)


# """二进制(str)->十六进制(str)"""
def bin2hex(bin):
    dec = int(bin, 2)
    return hex(dec)[2:]


if __name__ == '__main__':
    Sbox = getSBOX()
    
    
    # plaintext = []
    # ciphertext = []
    # IV = np.random.randint(0, 256, size=16, dtype=int)
    # for i in range(8000):
    #     plaintext.append(np.random.randint(0, 256, size=16))
    # bitNum = 128 * 8000
    # key = np.random.randint(0, 256, size=16)
    # print('plaintext size', bitNum)
    import random
    key = dec2bin(random.randint(0, 2**64-1))
    plaintext = []
    for i in range(16000):
        plaintext.append(dec2bin(random.randint(0, 2**64-1)))
    print('plaintext bit number', 64*16000)
    bitNum = 64 * 16000
    IV = dec2bin(random.randint(0, 2**64-1))
    ciphertext = []
    cpre = IV
    startEnc = time.process_time()
    for i in range(len(plaintext)):
        ci = desencode(XOR(cpre, plaintext[i]), key)
        ciphertext.append(ci)
        cpre = ci
    finishEnc = time.process_time()
    t = finishEnc-startEnc
    print('encode cost time:', t, 's, encode speed:', bitNum//t, 'bit/s')
    
    decodetext = []
    cpre = IV
    for i in range(len(ciphertext)):
        pi = XOR(desdecode(ciphertext[i], key), cpre)
        decodetext.append(pi)
        cpre = ciphertext[i]
    finishDec = time.process_time()
    t = finishDec - finishEnc
    print('decode cost time:', t, 's, encode speed:', bitNum // t, 'bit/s')
    dif = 0
    for i in range(len(plaintext)):
        dif += abs(int(plaintext[i], 2) - int(decodetext[i], 2))
    print('difference between plaintext and decoded text', dif)

    
    
