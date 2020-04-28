#!/usr/bin/python 
# -*-coding:utf-8 -*-
__author__ = '99K'

from enigma import Enigma, Roter


class EnigmaHacker:
    def __init__(self):
        self.encrypted_key = []
        self.letters = 'abcdefghijklmnopqrstuvwxyz'
        self.enigma = Enigma(r1='a', r2='a', r3='a', r4='a', r5='a', swap_num=0)
    
    def hack(self, encryption):
        self.encrypted_key = []
        for x in list(encryption):
            self.encrypted_key.append(self.letters.find(x))
        pre_msg = encryption[:3]
        post_msg = encryption[3:]
        result = []
        for order in [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]]:
            for i in self.letters:
                for j in self.letters:
                    for k in self.letters:
                        self.enigma.set_state(order, i, j, k)
                        key = self.enigma.encode(pre_msg)
                        res = self.enigma.encode(key)
                        if res == post_msg:
                            result.append([order, i, j, k])
        goodkey = []
        for order, i, j, k in result:
            enigma.set_state(order, i, j, k)
            validation_msg = enigma.encode(i + j + k) + enigma.encode(i + j + k)
            if encryption == validation_msg:
                print('Good key:', i + j + k)
                goodkey.append((order, i+j+k))
        return goodkey


if __name__ == '__main__':
    enigma = Enigma(r1='a', r2='a', r3='a', r4='a', r5='a', swap_num=0)
    key = 'abz'
    enigma.set_state([0, 2, 1], key[0], key[1], key[2])
    enigma_hacker = EnigmaHacker()
    encreption = enigma.encode(key) + enigma.encode(key)
    print('The key:', key)
    print('The encrypted:', encreption)
    hacked_result = enigma_hacker.hack(encreption)
    print('The order and the key:', hacked_result)