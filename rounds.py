from constants import *
from galois_field import *
import unittest


def grid_vertical(t):
    grid = []
    for i in range(len(t) // 4):
        grid.append([t[i], t[i + 4 * 1], t[i + 4 * 2], t[i + 4 * 3]])
    return grid


def de_grid_vertical(t):
    grid = []
    for i in range(len(t)):
        grid.append(t[0][i])
        grid.append(t[1][i])
        grid.append(t[2][i])
        grid.append(t[3][i])
    return grid


def AddRoundKey(text, key):
    """XOR text with key, element by element.
    The 2 inputs have to be of the same length, and the output also has that length."""
    text_xor = []
    for i in range(len(text)):
        text_xor.append(int(text[i]) ^ key[i])
    return text_xor


def SubBytes(text):
    """Lookup table, that uses the Rijndael S-Box. Substitutes element by element."""
    sub_bytes = []
    for i in text:
        sub_bytes.append(sbox[i])
    return sub_bytes


def inverse_SubBytes(text):
    """Reverse lookup table. Resubstitutes element by element."""
    sub_bytes = []
    for i in text:
        sub_bytes.append(inverse_sbox[i])
    return sub_bytes


def ShiftRows(text):
    """Reformats the list it was given, by putting it in a 4x4 grid. Then each row is shifted to the left 1 more than
    the previous row. The output is in the original list format, as opposed to the grid format that was used during
    the permutation."""
    grid = grid_vertical(text)
    rotated_key = []
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


def inverse_ShiftRows(text):
    """Reformats the list it was given, by putting it in a 4x4 grid. Then Shifts the rows back to their original
    position, namely each row 1 more to the right than the previous one. The output is in the original list format,
    as opposed to the grid format that was used during the permutation."""
    grid = grid_vertical(text)
    rotated_key = []
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


def MixColumns(text):
    """Uses finite fields and matrix multiplication, to mix the columns. Uses a predefined matrix for the
    multiplication."""
    grid = grid_vertical(text)
    mixed_columns = []
    for i in grid:
        mixed_columns.append(MM(i, Matrix))
    mixed_columns = de_grid_vertical(mixed_columns)
    return mixed_columns


def inverse_MixColumns(text):
    """Uses finite fields and matrix multiplication, to unmix the columns. Uses a different matrix for the
    multiplication than the direct function."""
    grid = grid_vertical(text)
    mixed_columns = []
    for i in grid:
        mixed_columns.append(MM(i, inverseMatrix))
    mixed_columns = de_grid_vertical(mixed_columns)
    return mixed_columns


def aes_encrypt_round(plaintext, key):
    """One standard round of encryption. Takes an input of the plaintext and the key, puts it through the SP-Network
    and returns the ciphertext of the same length as the two inputs."""
    ciphertext = SubBytes(plaintext)
    ciphertext = ShiftRows(ciphertext)
    ciphertext = MixColumns(ciphertext)
    ciphertext = AddRoundKey(ciphertext, key)
    return ciphertext


def aes_decrypt_round(ciphertext, key):
    """One standard round of decryption. Takes an input of the ciphertext and the key, puts it through the inverse
    SP-Network and returns a plaintext of the same length as the two inputs."""
    ciphertext = AddRoundKey(ciphertext, key)
    ciphertext = inverse_MixColumns(ciphertext)
    ciphertext = inverse_ShiftRows(ciphertext)
    plaintext = inverse_SubBytes(ciphertext)
    return plaintext


def aes_encrypt_round_final(plaintext, key):
    """In the final round of encryption, the MixColumns function is skipped, because it doesnt add security to the
    function as a whole."""
    ciphertext = SubBytes(plaintext)
    ciphertext = ShiftRows(ciphertext)
    ciphertext = AddRoundKey(ciphertext, key)
    return ciphertext


def aes_decrypt_round_first(ciphertext, key):
    """In the first round of decryption, the MixColumns function is skipped, so as to be the inverse of the
    encrypt_round_final function."""
    ciphertext = AddRoundKey(ciphertext, key)
    ciphertext = inverse_ShiftRows(ciphertext)
    plaintext = inverse_SubBytes(ciphertext)
    return plaintext


class TestStringMethods(unittest.TestCase):
    def test_aes_round(self):
        key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]
        plaintext = bytearray(
            [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a])
        self.assertEqual(plaintext, bytearray(aes_decrypt_round(aes_encrypt_round(plaintext, key), key)))

    def test_round_no_MixColumns(self):
        key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]
        plaintext = bytearray(
            [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a])
        self.assertEqual(plaintext, bytearray(aes_decrypt_round_first(aes_encrypt_round_final(plaintext, key), key)))


if __name__ == '__main__':
    unittest.main()