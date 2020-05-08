#!/usr/bin/python 
# -*-coding:utf-8 -*-
__author__ = '99K'

import numpy as np

from AES_S_BOX import generate_s_bos, generate_inv_s_box

s_box = generate_s_bos()
s_box_inv = generate_inv_s_box()


def addRoundKey(x, key):
    return x ^ key


def subBytes(x):
    row = x >> 4
    col = x & 0x0F
    res = s_box[row][col]
    return res


def shiftRows(state):
    for i in range(4):
        tmp = []
        for j in range(4):
            tmp.append(state[i * 4 + j])
        for j in range(4):
            state[i * 4 + j] = tmp[(j + 4 - i) % 4]

    return state


def gMulti(a, b):
    p = 0
    hbs = 0
    for i in range(8):
        if b & 1:
            p = p ^ a
        hbs = a & 0x80
        a = a << 1
        if hbs:
            a = a ^ 0x1b
        b = b >> 1
    return p

def gfMul2(s):
    res = s << 1
    a7 = res & 0x100
    if a7 != 0:
        res = res & 0xff
        res = res ^ 0x1b
    return res

def gfMul3(s):
    return gfMul2(s) ^ s
def gfMul4(s):
    return gfMul2(gfMul2(s))
def gfMul8(s):
    return gfMul2(gfMul4(s))
def gfMul9(s):
    return gfMul8(s) ^ s
def gfMul11(s):
    return gfMul9(s) ^ gfMul2(s)
def gfMul12(s):
    return gfMul8(s)^gfMul4(s)
def gfMul13(s):
    return gfMul12(s) ^ s
def gfMul14(s):
    return gfMul12(s) ^ gfMul2(s)


def gfMul(n, s):
    if n == 1:
        res = s
    elif n == 2:
        res = gfMul2(s)
    elif n == 3:
        res = gfMul3(s)
    elif n == 9:
        res = gfMul9(s)
    elif n == 11:
        res = gfMul11(s)
    elif n == 13:
        res = gfMul13(s)
    elif n == 14:
        res = gfMul14(s)
    else:
        print('invalid input s', s)
    return res


def mixColumns(state):
    coef = [0x2, 0x3, 0x1, 0x1]
    for i in range(4):
        tmp = []
        for j in range(4):
            tmp.append(state[i + j * 4])
        for j in range(4):
            state[i + j * 4] = gfMul(coef[(-j + 4) % 4], tmp[0]) ^ \
                               gfMul(coef[(-j + 5) % 4], tmp[1]) ^ \
                               gfMul(coef[(-j + 6) % 4], tmp[2]) ^ \
                               gfMul(coef[(-j + 7) % 4], tmp[3])
    return state


def oneRound_encode(plaintext, key):
    state = np.zeros(16, dtype=int)
    for i, x in enumerate(plaintext):
        state[i] = subBytes(x)
    
    state = shiftRows(state)
    state = mixColumns(state)
    for i in range(16):
        state[i] = addRoundKey(state[i], key[i])
    
    return state


def invShiftRows(state):
    for i in range(4):
        tmp = []
        for j in range(4):
            tmp.append(state[i * 4 + j])
        for j in range(4):
            state[i * 4 + j] = tmp[(j + 4 + i) % 4]
    return state


def invSubBytes(x):
    row = x >> 4
    col = x & 0x0F
    res = s_box_inv[row][col]
    return res


def invMixColumns(state):
    coef = [0xe, 0xb, 0xd, 0x9]
    for i in range(4):
        tmp = []
        for j in range(4):
            tmp.append(state[i + j * 4])
        for j in range(4):
            state[i + j * 4] = gfMul(coef[(-j + 4) % 4], tmp[0]) ^ \
                               gfMul(coef[(-j + 5) % 4], tmp[1]) ^ \
                               gfMul(coef[(-j + 6) % 4], tmp[2]) ^ \
                               gfMul(coef[(-j + 7) % 4], tmp[3])
    return state


def oneRound_decode(ciphertext, key):
    state = invShiftRows(ciphertext)
    for i, x in enumerate(state):
        state[i] = invSubBytes(x)
    for i in range(16):
        state[i] = addRoundKey(state[i], key[i])
    state = invMixColumns(state)
    return state


if __name__ == '__main__':
    input_data = np.random.randint(0, 256, size=16)
    print('original ', input_data)
    state = shiftRows(state=input_data)
    print('shifted  ', state)
    state = invShiftRows(state)
    print('invshift ', state, ', dif:', state - input_data)
    state = mixColumns(state)
    print('mixcolnm ', state)
    state = invMixColumns(state)
    print('invMixcol', state, ', dif:', state - input_data)
    
    for i, x in enumerate(state):
        state[i] = subBytes(x)
    print('subbyte  ', state)
    for i, x in enumerate(state):
        state[i] = invSubBytes(x)
    print('invSubbyte', state, ', dif:', state - input_data )
    
    key = np.random.randint(0, 256, size=16)
    for i, x in enumerate(state):
        state[i] = addRoundKey(x, key[i])
    print('add key   ', state)
    for i, x in enumerate(state):
        state[i] = addRoundKey(x, key[i])
    print('add key   ', state)
    
    print('plaintext ', input_data)
    # state = oneRound_encode(input_data, key)
    # print('ciphertext', state)
    # state = oneRound_decode(state, key)
    # print('decodetext', state)
    
    # for b in state:
    #     print(b)
    #
    # print('%#x' % state)
