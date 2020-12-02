from constants import *
from galois_field import *
import unittest


def grid_vertical(t):
    grid = []
    for i in range(len(t)//4):
        grid.append([t[i],t[i+4*1],t[i+4*2],t[i+4*3]])
    return grid

def de_grid_vertical(t):
    grid = []
    for i in range(len(t)):
        grid.append(t[0][i])
        grid.append(t[1][i])
        grid.append(t[2][i])
        grid.append(t[3][i])
    return grid


def AddRoundKey(text,key):
    xored_text = []
    for i in range(len(text)):
        xored_text.append(int(text[i]) ^ key[i])
    return xored_text


def SubBytes(t):
    sub_bytes = []
    for i in t:
        sub_bytes.append(sbox[i])
    return sub_bytes

def inverse_SubBytes(t):
    sub_bytes = []
    for i in t:
        sub_bytes.append(inverse_sbox[i])
    return sub_bytes


def ShiftRows(t):
    grid = grid_vertical(t)
    rotated_key = [  ]
    row0 = grid[0]
    row1 = grid[1][1:] + grid[1][:1]
    row2 = grid[2][2:] + grid[2][:2]
    row3 = grid[3][3:] + grid[3][:3]
    rotated_key.append(row0)
    rotated_key.append(row1)
    rotated_key.append(row2)
    rotated_key.append(row3)
    rotated_key = de_grid_vertical(rotated_key)
    return rotated_key

def inverse_ShiftRows(t):
    grid = grid_vertical(t)
    rotated_key = [  ]
    row0 = grid[0]
    row1 = grid[1][3:] + grid[1][:3]
    row2 = grid[2][2:] + grid[2][:2]
    row3 = grid[3][1:] + grid[3][:1]
    rotated_key.append(row0)
    rotated_key.append(row1)
    rotated_key.append(row2)
    rotated_key.append(row3)
    rotated_key = de_grid_vertical(rotated_key)
    return rotated_key


def MixColumns(t):
    grid = grid_vertical(t)
    mixedcolumns = []
    for i in grid:
        mixedcolumns.append(MM(i, Matrix))
    mixedcolumns = de_grid_vertical(mixedcolumns)
    return mixedcolumns

def inverse_MixColumns(t):
    grid = grid_vertical(t)
    mixedcolumns = []
    for i in grid:
        mixedcolumns.append(MM(i, inverseMatrix))
    mixedcolumns = de_grid_vertical(mixedcolumns)
    return mixedcolumns


def aes_encrypt_round(plaintext,key):
    cyphertext = SubBytes(plaintext)
    cyphertext = ShiftRows(cyphertext)
    cyphertext = MixColumns(cyphertext)
    cyphertext = AddRoundKey(cyphertext,key)
    return cyphertext

def aes_decrypt_round(cyphertext,key):
    cyphertext = AddRoundKey(cyphertext,key)
    cyphertext = inverse_MixColumns(cyphertext)
    cyphertext = inverse_ShiftRows(cyphertext)
    plaintext = inverse_SubBytes(cyphertext)
    return plaintext

def aes_encrypt_round_final(plaintext,key):
    cyphertext = SubBytes(plaintext)
    cyphertext = ShiftRows(cyphertext)
    cyphertext = AddRoundKey(cyphertext,key)
    return cyphertext

def aes_decrypt_round_first(cyphertext,key):
    cyphertext = AddRoundKey(cyphertext,key)
    cyphertext = inverse_ShiftRows(cyphertext)
    plaintext = inverse_SubBytes(cyphertext)
    return plaintext

class TestStringMethods(unittest.TestCase):
    def test_aes_round(self):
        key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]
        plaintext = bytearray([0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a])
        self.assertEqual(plaintext, bytearray(aes_decrypt_round(aes_encrypt_round(plaintext,key),key)))

    def test_round_no_MixColumns(self):
        key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]
        plaintext = bytearray([0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a])
        self.assertEqual(plaintext, bytearray(aes_decrypt_round_first(aes_encrypt_round_final(plaintext,key),key)))

if __name__ == '__main__':
    unittest.main()