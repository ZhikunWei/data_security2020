#!/usr/bin/python 
# -*-coding:utf-8 -*-
__author__ = '99K'

import random
import time

SM4_FK = (0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC)
SM4_CK = (0X00070E15, 0X1C232A31, 0X383F464D, 0X545B6269,
          0X70777E85, 0X8C939AA1, 0XA8AFB6BD, 0XC4CBD2D9,
          0XE0E7EEF5, 0XFC030A11, 0X181F262D, 0X343B4249,
          0X50575E65, 0X6C737A81, 0X888F969D, 0XA4ABB2B9,
          0XC0C7CED5, 0XDCE3EAF1, 0XF8FF060D, 0X141B2229,
          0X30373E45, 0X4C535A61, 0X686F767D, 0X848B9299,
          0XA0A7AEB5, 0XBCC3CAD1, 0XD8DFE6ED, 0XF4FB0209,
          0X10171E25, 0X2C333A41, 0X484F565D, 0X646B7279)

SM4_SBOX = [0XD6, 0X90, 0XE9, 0XFE, 0XCC, 0XE1, 0X3D, 0XB7, 0X16, 0XB6, 0X14, 0XC2, 0X28, 0XFB, 0X2C, 0X05,
            0X2B, 0X67, 0X9A, 0X76, 0X2A, 0XBE, 0X04, 0XC3, 0XAA, 0X44, 0X13, 0X26, 0X49, 0X86, 0X06, 0X99,
            0X9C, 0X42, 0X50, 0XF4, 0X91, 0XEF, 0X98, 0X7A, 0X33, 0X54, 0X0B, 0X43, 0XED, 0XCF, 0XAC, 0X62,
            0XE4, 0XB3, 0X1C, 0XA9, 0XC9, 0X08, 0XE8, 0X95, 0X80, 0XDF, 0X94, 0XFA, 0X75, 0X8F, 0X3F, 0XA6,
            0X47, 0X07, 0XA7, 0XFC, 0XF3, 0X73, 0X17, 0XBA, 0X83, 0X59, 0X3C, 0X19, 0XE6, 0X85, 0X4F, 0XA8,
            0X68, 0X6B, 0X81, 0XB2, 0X71, 0X64, 0XDA, 0X8B, 0XF8, 0XEB, 0X0F, 0X4B, 0X70, 0X56, 0X9D, 0X35,
            0X1E, 0X24, 0X0E, 0X5E, 0X63, 0X58, 0XD1, 0XA2, 0X25, 0X22, 0X7C, 0X3B, 0X01, 0X21, 0X78, 0X87,
            0XD4, 0X00, 0X46, 0X57, 0X9F, 0XD3, 0X27, 0X52, 0X4C, 0X36, 0X02, 0XE7, 0XA0, 0XC4, 0XC8, 0X9E,
            0XEA, 0XBF, 0X8A, 0XD2, 0X40, 0XC7, 0X38, 0XB5, 0XA3, 0XF7, 0XF2, 0XCE, 0XF9, 0X61, 0X15, 0XA1,
            0XE0, 0XAE, 0X5D, 0XA4, 0X9B, 0X34, 0X1A, 0X55, 0XAD, 0X93, 0X32, 0X30, 0XF5, 0X8C, 0XB1, 0XE3,
            0X1D, 0XF6, 0XE2, 0X2E, 0X82, 0X66, 0XCA, 0X60, 0XC0, 0X29, 0X23, 0XAB, 0X0D, 0X53, 0X4E, 0X6F,
            0XD5, 0XDB, 0X37, 0X45, 0XDE, 0XFD, 0X8E, 0X2F, 0X03, 0XFF, 0X6A, 0X72, 0X6D, 0X6C, 0X5B, 0X51,
            0X8D, 0X1B, 0XAF, 0X92, 0XBB, 0XDD, 0XBC, 0X7F, 0X11, 0XD9, 0X5C, 0X41, 0X1F, 0X10, 0X5A, 0XD8,
            0X0A, 0XC1, 0X31, 0X88, 0XA5, 0XCD, 0X7B, 0XBD, 0X2D, 0X74, 0XD0, 0X12, 0XB8, 0XE5, 0XB4, 0XB0,
            0X89, 0X69, 0X97, 0X4A, 0X0C, 0X96, 0X77, 0X7E, 0X65, 0XB9, 0XF1, 0X09, 0XC5, 0X6E, 0XC6, 0X84,
            0X18, 0XF0, 0X7D, 0XEC, 0X3A, 0XDC, 0X4D, 0X20, 0X79, 0XEE, 0X5F, 0X3E, 0XD7, 0XCB, 0X39, 0X48]


def IsHexCharacter(hexstring):
    base = [str(x) for x in range(0, 10)] + [chr(y) for y in range(ord('A'), ord('A') + 6)]
    for character in hexstring:
        if character.upper() not in base:
            return False
    return True


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


def _line_conv_L(srcdata):
    return srcdata ^ lrotate(srcdata, 2) ^ lrotate(srcdata, 10) ^ lrotate(srcdata, 18) ^ lrotate(srcdata, 24)


def _line_conv_LN(srcdata):
    return srcdata ^ lrotate(srcdata, 13) ^ lrotate(srcdata, 23)


def _sbox_conv(srcdata):
    return SM4_SBOX[srcdata]


def _no_line_conv(srcdata):
    four = (SM4_SBOX[srcdata & 0x000000FF]) & 0x000000FF
    three = (SM4_SBOX[(srcdata & 0x0000FF00) >> 8] << 8) & 0x0000FF00
    secod = (SM4_SBOX[(srcdata & 0x00FF0000) >> 16] << 16) & 0x00FF0000
    first = (SM4_SBOX[(srcdata & 0xFF000000) >> 24] << 24) & 0xFF000000
    return first | secod | three | four
    # return (SM4_SBOX[first] << 24) | (SM4_SBOX[secod] << 16) | (SM4_SBOX[three] << 8) | (SM4_SBOX[four])


def _t_conv(srcdata):
    return _line_conv_L(_no_line_conv(srcdata))


def _tn_conv(srcdata):
    return _line_conv_LN(_no_line_conv(srcdata))


def _generate_ext_keys(initkey):
    MK = (initkey[:8], initkey[8:16], initkey[16:24], initkey[24:])
    K = []
    for i in range(0, len(MK)):
        K.append(Xor(int(MK[i], 16), SM4_FK[i]))
    
    for i in range(0, 32):
        xorrsp = Xor(Xor(Xor(K[i + 1], K[i + 2]), K[i + 3]), SM4_CK[i])
        K.append(Xor(K[i], _tn_conv(xorrsp)))
    
    return K[4:]


def dec2bin(dec):
    return bin(dec)[2:].zfill(64)


def bin2hex(bin):
    dec = int(bin, 2)
    return hex(dec)[2:]


def dec2hex(dec):
    return hex(dec)[2:]


def hex2bin(hex):
    dec = int(hex, 16)
    return bin(dec)[2:].zfill(64)


def sm4encode(msg, rkeys):
    X = [int(msg[:8], 16), int(msg[8:16], 16), int(msg[16:24], 16), int(msg[24:], 16)]
    for i in range(0, 32):
        xorrsp = Xor(Xor(Xor(X[i + 1], X[i + 2]), X[i + 3]), rkeys[i])
        X.append(Xor(X[i], _t_conv(xorrsp)))
    return '%08X%08X%08X%08X' % (X[35], X[34], X[33], X[32])


def sm4decode(msg, rkeys):
    X = [int(msg[:8], 16), int(msg[8:16], 16), int(msg[16:24], 16), int(msg[24:], 16)]
    for i in range(0, 32):
        xorrsp = Xor(Xor(Xor(X[i + 1], X[i + 2]), X[i + 3]), rkeys[31 - i])
        X.append(Xor(X[i], _t_conv(xorrsp)))
    return '%08X%08X%08X%08X' % (X[35], X[34], X[33], X[32])


if __name__ == '__main__':
    key = dec2hex(random.randint(0, 2 ** 128 - 1))
    key = '0' * (32-len(key)) + key
    extkeys = _generate_ext_keys(key)
    plaintext = []
    for i in range(8000):
        plaintext.append(dec2hex(random.randint(0, 2 ** 128 - 1)))
        while len(plaintext[i]) < 32:
            plaintext[i] = '0' + plaintext[i]
        if len(plaintext[i]) < 32:
            print(len(plaintext[i]))
    bitNum = 128 * 8000
    print('plaintext bit number', bitNum)
    IV = dec2hex(random.randint(0, 2 ** 128 - 1))
    IV = '0' * (32-len(IV)) + IV
    print('key', key)
    print('IV ', IV)
    cpre = IV
    ciphertext = []
    startEnc = time.process_time()
    for i in range(len(plaintext)):
        ci = sm4encode('%032X' % Xor(int(cpre, 16), int(plaintext[i], 16)), extkeys)
        ciphertext.append(ci)
        cpre = ci
    finishEnc = time.process_time()
    t = finishEnc - startEnc
    print('encode cost time:', t, 's, encode speed:', bitNum // t, 'bit/s')
    
    cpre = IV
    decodetext = []
    for i in range(len(ciphertext)):
        d = sm4decode(ciphertext[i], extkeys)
        pi = '%032X' % Xor(int(cpre, 16), int(d, 16))
        decodetext.append(pi)
        cpre = ciphertext[i]
    finishDec = time.process_time()
    t = finishDec - finishEnc
    print('decode cost time:', t, 's, encode speed:', bitNum // t, 'bit/s')
    dif = 0
    for i in range(len(plaintext)):
        # print(plaintext[i], decodetext[i])
        dif += abs(int(plaintext[i], 16) - int(decodetext[i], 16))
    print('difference between plaintext and decoded text', dif)
