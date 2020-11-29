import secrets
from galois_field import MM
from constants import *

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

key = [61, 20, 224, 15, 10, 78, 29, 58, 245, 44, 85, 182, 255, 36, 120, 204]
#print(key)

key_short = [61, 20, 224, 15]
#print(key_short)

plaintext = bytearray("plaintextabcdefg","utf8")

def keyexpansioncore(key):
    rotated_key = key[1:] + key[:1]
    sub_key = []
    for i in rotated_key:
        sub_key.append(sbox[i])

    return sub_key   
   
def gen_next_key(key):
    nextkey = []
    for i in range(0,len(key),4):
        nextkey += keyexpansioncore(key[i:i+4])
    return nextkey

def keyexpansion11(key):
    keys = [key]
    for i in range(10):
        key = gen_next_key(key)
        keys.append(key)
    return keys    

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

def aes_encrypt_round_final(plaintext,key):
    cyphertext = SubBytes(plaintext)
    cyphertext = ShiftRows(cyphertext)
    cyphertext = AddRoundKey(cyphertext,key)
    return cyphertext

def aes_encrypt(plaintext,key):    
    keys = keyexpansion11(key)
    cyphertext = AddRoundKey(plaintext,key)
    for k in keys[1:-1]:
        cyphertext = aes_encrypt_round(cyphertext,k)
    cyphertext = aes_encrypt_round_final(cyphertext,keys[-1])   
    return cyphertext    

def aes_decrypt_round(cyphertext,key):
    cyphertext = inverse_MixColumns(cyphertext)
    cyphertext = inverse_ShiftRows(cyphertext)
    cyphertext = inverse_SubBytes(cyphertext)
    plaintext = AddRoundKey(cyphertext,key)
    return plaintext

def aes_decrypt_round_first(cyphertext,key):
    cyphertext = inverse_ShiftRows(cyphertext)
    cyphertext = inverse_SubBytes(cyphertext)
    plaintext = AddRoundKey(cyphertext,key)
    return plaintext

def aes_decrypt(cyphertext,key):
    keys = keyexpansion11(key)
    cyphertext = AddRoundKey(cyphertext, keys[-1])
    cyphertext = aes_decrypt_round_first(cyphertext,keys[-2])
    for k in keys[-3::-1]:
        cyphertext = aes_decrypt_round(cyphertext,k)
    return cyphertext

cyphertext = aes_encrypt(plaintext,key)

decrypted_plaintext = aes_decrypt(cyphertext,key)

def printhex(t, l):
    print(t, "[", end='')
    for i in l:
        print(hex(i), end=', ')
    print("]")

print('plaintext:  ', plaintext)
print('decrypted:  ', bytearray(decrypted_plaintext))
printhex('plaintext:  ', plaintext)
printhex('cyphertext: ', cyphertext)
printhex('decrypted:  ', decrypted_plaintext)
print('plaintext == decrypted_plaintext: ', plaintext == bytearray(decrypted_plaintext))
