#!/usr/bin/python 
# -*-coding:utf-8 -*-
__author__ = '99K'

import numpy as np

from utils import addRoundKey, subBytes, shiftRows, \
    invShiftRows, invSubBytes, mixColumns, invMixColumns


def aes_encode(plaintext, keys):
    state = np.zeros(16, dtype=int)
    for i, x in enumerate(plaintext):
        state[i] = addRoundKey(x, keys[0][i])
    for i in range(1, 10):
        for j, x in enumerate(state):
            state[j] = subBytes(x)
        state = shiftRows(state)
        state = mixColumns(state)
        for j in range(16):
            state[j] = addRoundKey(state[j], keys[i][j])
    for i, x in enumerate(state):
        state[i] = subBytes(x)
    state = shiftRows(state)
    for i, x in enumerate(state):
        state[i] = addRoundKey(x, keys[-1][i])
    return state


def aes_decode(ciphertext, keys):
    state = np.zeros(16, dtype=int)
    for i, x in enumerate(ciphertext):
        state[i] = addRoundKey(x, keys[-1][i])
    for i in range(1, 10):
        state = invShiftRows(state)
        for j, x in enumerate(state):
            state[j] = invSubBytes(x)
        for j in range(16):
            state[j] = addRoundKey(state[j], keys[-1-i][j])
        state = invMixColumns(state)
    state = invShiftRows(state)
    for i, x in enumerate(state):
        state[i] = invSubBytes(x)
    for i, x in enumerate(state):
        state[i] = addRoundKey(x, keys[0][i])
    return state


def extendKey(key0):
    roundCon = [0, 0x01000000, 0x02000000, 0x04000000, 0x08000000,
                0x10000000, 0x20000000, 0x40000000, 0x80000000,
                0x1b000000, 0x36000000]
    w = []
    # print('key0', key0)
    for i in range(4):
        w.append(((key0[4 * i + 0] << 24) & 0xffffffff) + ((key0[4 * i + 1] << 16) & 0xffffffff) +
                 ((key0[4 * i + 2] << 8) & 0xffffffff) + (key0[4 * i + 3] & 0xffffffff))
    # print('w   %#x' % w[3])
    for i in range(4, 44):
        tmp = w[i - 1]
        if i % 4 == 0:
            tmp = (tmp >> 24) + ((tmp & 0x00ffffff) << 8)
            # print('tmp %#x' % tmp)
            tmp_bytes = [(tmp & 0xff000000) >> 24, (tmp & 0x00ff0000) >> 16,
                         (tmp & 0x0000ff00) >> 8, (tmp & 0x000000ff)]
            # print('tmp_bytes', ['%#x' % x for x in tmp_bytes])
            tmp = (subBytes(tmp_bytes[0]) << 24) + (subBytes(tmp_bytes[1]) << 16) + \
                  (subBytes(tmp_bytes[2]) << 8) + subBytes(tmp_bytes[3])
            tmp = tmp ^ roundCon[i // 4]
        w.append(w[i - 4] ^ tmp)
    keys = []
    for i in range(11):
        key = np.zeros(16, dtype=int)
        k = w[i * 4:(i + 1) * 4]
        for j in range(4):
            key[4 * j + 0] = (k[j] & 0xff000000) >> 24
            key[4 * j + 1] = (k[j] & 0x00ff0000) >> 16
            key[4 * j + 2] = (k[j] & 0x0000ff00) >> 8
            key[4 * j + 3] = (k[j] & 0x000000ff)
        keys.append(key)
    # print('key0', keys[0])
    return keys


if __name__ == '__main__':
    input_data = np.random.randint(0, 256, size=16)
    key = np.random.randint(0, 256, size=16)
    round_keys = extendKey(key)

    print('plaintext   ', input_data)
    state = aes_encode(input_data, round_keys)
    print('ciphertext  ', state)
    state = aes_decode(state, round_keys)
    print('decoded text', state)
