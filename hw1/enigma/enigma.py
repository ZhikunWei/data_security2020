#!/usr/bin/python 
# -*-coding:utf-8 -*-
__author__ = '99K'

# simple implementation of enigma code machine

import random


class Roter:
    def __init__(self, init_offset='a', change_table=None):
        self.letters = 'abcdefghijklmnopqrstuvwxyz'
        if change_table is None:
            self.change_table = [-1] * 26
            for i in range(26):
                value = random.randint(0, 25)
                while value in self.change_table:
                    value += 1
                    value %= 26
                self.change_table[i] = value
        else:
            self.change_table = []
            for m in list(change_table):
                self.change_table.append(self.letters.find(m))
        self.cur_offset = self.letters.find(init_offset)
    
    def set_state(self, state):
        self.cur_offset = self.letters.find(state)
    
    def rotate(self):
        self.cur_offset += 1
        self.cur_offset %= 26
    
    def encode(self, x):
        one_round = False
        if self.cur_offset % 26 == 0:
            one_round = True
        encryption = self.change_table[(self.cur_offset + x) % 26]
        return one_round, encryption
    
    def decode(self, code):
        # print(code)
        for i in range(26):
            if code == self.change_table[i]:
                return (i - self.cur_offset + 26) % 26


class Plugboard:
    def __init__(self, num_swap, reflection=None):
        self.letters = 'abcdefghijklmnopqrstuvwxyz'
        if reflection is None:
            self.plug_board = [x for x in range(26)]
            all_letters = [x for x in range(26)]
            chosen = random.sample(all_letters, num_swap)
            remain = [x for x in all_letters if x not in chosen]
            chosen2 = random.sample(remain, num_swap)
            for x, y in zip(chosen, chosen2):
                self.plug_board[x] = y
                self.plug_board[y] = x
        else:
            self.plug_board = []
            for m in list(reflection):
                self.plug_board.append(self.letters.find(m))
    
    def __call__(self, code):
        return self.plug_board[code]


class Enigma:
    def __init__(self, r1='a', r2='a', r3='a', r4='a', r5='a', swap_num=6):
        self.letters = 'abcdefghijklmnopqrstuvwxyz'
        self.int2char_table = list(self.letters)
        self.all_roters = []
        self.all_roters.append(Roter(r1, 'ekmflgdqvzntowyhxuspaibrcj'))
        self.all_roters.append(Roter(r2, 'ajdksiruxblhwtmcqgznpyfvoe'))
        self.all_roters.append(Roter(r3, 'bdfhjlcprtxvznyeiwgakmusqo'))
        self.all_roters.append(Roter(r4, 'esovpzjayquirhxlnftgkdcmwb'))
        self.all_roters.append(Roter(r5, 'vzbrgityupsdnhlxawmjqofeck'))
        self.roters = self.all_roters[:3]
        self.plug_board = Plugboard(swap_num)
        self.reflection = Plugboard(13, 'yruhqsldpxngokmiebfzcwvjat')
        print('roter1', self.all_roters[0].change_table)
        print('roter2', self.all_roters[1].change_table)
        print('roter3', self.all_roters[2].change_table)
        print('roter4', self.all_roters[3].change_table)
        print('roter5', self.all_roters[4].change_table)
        print('plug board', self.plug_board.plug_board)
        print('reflection', self.reflection.plug_board)
    
    def encode(self, msg):
        list_int = self.char2int(msg)
        result_int = []
        for x in list_int:
            x = self.plug_board(x)
            self.roters[0].rotate()
            one_round1, x = self.roters[0].encode(x)
            if one_round1:
                self.roters[1].rotate()
            one_round2, x = self.roters[1].encode(x)
            if one_round2:
                self.roters[2].rotate()
            one_round3, x = self.roters[2].encode(x)
            x = self.reflection(x)
            x = self.roters[2].decode(x)
            x = self.roters[1].decode(x)
            x = self.roters[0].decode(x)
            x = self.plug_board(x)
            result_int.append(x)
        result_str = self.int2char(result_int)
        return result_str
    
    def set_state(self, roters, r1, r2, r3):
        self.roters.clear()
        self.roters = [self.all_roters[i] for i in roters]
        self.roters[0].set_state(r1)
        self.roters[1].set_state(r2)
        self.roters[2].set_state(r3)
        
    def char2int(self, msg_char):
        int_list = []
        msg_char = list(msg_char)
        for m in msg_char:
            int_list.append(self.letters.find(m))
        return int_list
    
    def int2char(self, int_list):
        result = ''
        for x in int_list:
            result += self.int2char_table[x]
        return result


if __name__ == '__main__':
    enigma = Enigma(r1='a', r2='a', r3='a', r4='a', r5='a', swap_num=6)
    
    # choose #0,#1,#3 roters, and set their init offset to 0, 3, 5
    enigma.set_state([0, 1, 3], 'a', 'c', 'e')
    msg = input('Plaintext(only lower case): ')
    print('The plaintext:', msg)
    result = enigma.encode(msg)
    print('The encrypted:', result)
    enigma.set_state([0, 1, 3], 'a', 'c', 'e')
    result = enigma.encode(result)
    print('The decode msg:', result)
