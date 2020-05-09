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


def xor(*words):
    first, *words = words
    result = first
    for word in words:
        result = xor_2(result, word)
    return result


def xor_2(a, b):
    return ''.join('0' if i == j else '1' for i, j in zip(a, b))


def lane(state, x, y):
    lane_ = ''.join(state[x][y])
    return lane_


def change_conventions(state):
    state_ = [[['' for z in range(64)] for y in range(5)] for x in range(5)]
    for x in range(5):
        for y in range(5):
            state_[x][y] = list(lane(state, (x + 2) % 5, (y + 2) % 5))
    return state_


def form_state(data):
    assert len(data) == 1600
    # create an empty state of 5x5x64 dimensions
    state = [[['' for z in range(64)] for y in range(5)] for x in range(5)]
    # replace the items of state with that of data
    for x in range(5):
        for y in range(5):
            for z in range(64):
                state[x][y][z] = data[64 * ((5 * y) + x) + z]
    return change_conventions(state)


def theta(state):
    def C(x, z):
        return xor(*[state[x][i][z] for i in range(5)])
    
    def D(x, z):
        return xor_2(C((x - 1) % 5, z), C((x + 1) % 5, (z - 1) % 64))
    
    state_ = [[['' for z in range(64)] for y in range(5)] for x in range(5)]
    for x in range(5):
        for y in range(5):
            for z in range(64):
                state_[x][y][z] = xor_2(state[x][y][z], D(x, z))
    return state_


def rot(word, shift):
    shift = shift % len(word)
    return word[-shift:] + word[:-shift]


def rho(state):
    rot_vals = [[153, 231, 3, 10, 171],
                [55, 276, 36, 300, 6],
                [28, 91, 0, 1, 190],
                [120, 78, 210, 66, 253],
                [21, 136, 105, 45, 15]]
    state_ = [[['' for z in range(64)] for y in range(5)] for x in range(5)]
    for x in range(5):
        for y in range(5):
            state_[y][((2 * x) + (3 * y)) % 5] = list(
                rot(lane(state, x, y), rot_vals[(y + 2) % 5][(x + 2) % 5] % 64))
    return state_


def pi(state):
    state_ = [[['' for z in range(64)] for y in range(5)] for x in range(5)]
    for x in range(5):
        for y in range(5):
            for z in range(64):
                state_[x][y][z] = state[(x + (3 * y)) % 5][x][z]
    return state_


def chi(state):
    state_ = [[['' for z in range(64)] for y in range(5)] for x in range(5)]
    
    for x in range(5):
        for y in range(5):
            state_[x][y] = list(xor_2(lane(state, x, y), bin(
                (int(lane(state, (x + 1) % 5, y), 2) ^ 1) & int(lane(state, (x + 2) % 5, y), 2))[
                                                         2:].zfill(64)))
    return state_


def iota(state, round_count):
    RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
          0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
          0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
          0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
          0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
          0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008, ]
    state_ = [[['' for z in range(64)] for y in range(5)] for x in range(5)]
    for x in range(5):
        for y in range(5):
            state_[x][y] = list(xor_2(lane(state, x, y), bin(RC[round_count])[2:].zfill(64)))
    return state_


def _round(b, round_count):
    b = theta(b)
    b = rho(b)
    b = pi(b)
    b = chi(b)
    b = iota(b, round_count)
    return b


def plane(state, y):
    return ''.join(lane(state, i, y) for i in range(5))


def f(r, c):
    b = r + c
    state = form_state(b)
    rounds = 24
    for i in range(rounds):
        round_count = i
        state = _round(state, round_count)
    unpacked_state = ''.join(plane(state, i) for i in range(5))
    return unpacked_state[:1088], unpacked_state[1088:]


def bin2hex(bin):
    dec = int(bin, 2)
    return hex(dec)[2:]


def sha3_256(msg):
    r = '0' * 1088
    c = '0' * (1600 - 1088)
    chunk = chunks(msg, 1088)
    for block in chunk:
        fInp = xor_2(block, r)
        r, c = f(fInp, c)
    value = r[:256]
    return bin2hex(value)


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
    while len(msg) % 1088 != 0:
        msg += '0'
    
    start = time.process_time()
    hashvalue = sha3_256(msg)
    finish = time.process_time()
    t = finish - start
    print('hash time', t, 'speed ', len(msg) // t, 'bit/s')
    print('hash value', hashvalue)
