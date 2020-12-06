import unittest

from constants import sbox, Rcon


def regroup(key):
    """16 byte key is regrouped into a 4 word key (A word is 4 bytes
    long)"""
    words = []
    for i in range(0, 16, 4):
        currword = (key[i + 0] << 24) + (key[i + 1] << 16) + (
                    key[i + 2] << 8) + key[i + 3]
        words.append(currword)
    return words


def ungroup(words):
    """The 4 word key is regrouped into a 16 byte key (A word is 4 bytes
    long)."""
    key = []
    for w in words:
        for byteindex in range(0, 31, 8):
            byte = 0
            byte = (w >> 24 - byteindex) & 0xff
            key.append(byte)
    return key


def subword(word):
    """Lookup table, that uses the Rijndael S-Box. Substitutes element by
    element."""
    sword = 0
    for i in range(0, 31, 8):
        byteindex = 24 - i
        byte = 0xff & word >> byteindex
        sword <<= 8
        sword |= sbox[byte]
    return sword


def rotword(word):
    """Rotates words, element by element. Similar to ShiftRow function."""
    b0 = word >> 24
    return 0xffffffff & ((word << 8) | b0)


def keyexpansion11(key):
    """Expands the key. N is the number of words in a key, R is the number
    of rounds(and also the amount of keys we have in the end). The output
    is a list, with list elements. These lists contain the keys
    themselves """
    N = 4
    R = 11
    words = regroup(key)
    for i in range(N, N * R):
        if i % N == 0:
            Rconi = Rcon[i // N]
            Win = words[i - N]
            Wsubrot = subword(rotword(words[-1]))
            words.append(Win ^ Rconi ^ Wsubrot)
        else:
            words.append(words[-1] ^ words[i - N])
    words = ungroup(words)
    keys = []
    for i in range(0, 11 * 16, 16):
        keys.append(words[i:i + 16])
    return keys


class TestStringMethods(unittest.TestCase):
    def test_regroup_keys(self):
        words = [0x01122334, 0x45566778, 0x899aabbc, 0xcddeeff0]
        key = [0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9a,
               0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0]
        self.assertEqual(words, regroup(key))

    def test_ungroup_keys(self):
        words = [0x01122334, 0x45566778, 0x899aabbc, 0xcddeeff0]
        key = [0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9a,
               0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0]
        self.assertEqual(key, ungroup(words))

    def test_rotword(self):
        self.assertEqual(0x34567812, rotword(0x12345678))

    def test_keyexpansion11_NIST(self):
        key = [0x54, 0x68, 0x61, 0x74, 0x73, 0x20, 0x6D, 0x79, 0x20, 0x4B,
               0x75, 0x6E, 0x67, 0x20, 0x46, 0x75]
        expanded = [
            [0x54, 0x68, 0x61, 0x74, 0x73, 0x20, 0x6D, 0x79, 0x20, 0x4B,
             0x75, 0x6E, 0x67, 0x20, 0x46, 0x75],
            [0xE2, 0x32, 0xFC, 0xF1, 0x91, 0x12, 0x91, 0x88, 0xB1, 0x59,
             0xE4, 0xE6, 0xD6, 0x79, 0xA2, 0x93],
            [0x56, 0x08, 0x20, 0x07, 0xC7, 0x1A, 0xB1, 0x8F, 0x76, 0x43,
             0x55, 0x69, 0xA0, 0x3A, 0xF7, 0xFA],
            [0xD2, 0x60, 0x0D, 0xE7, 0x15, 0x7A, 0xBC, 0x68, 0x63, 0x39,
             0xE9, 0x01, 0xC3, 0x03, 0x1E, 0xFB],
            [0xA1, 0x12, 0x02, 0xC9, 0xB4, 0x68, 0xBE, 0xA1, 0xD7, 0x51,
             0x57, 0xA0, 0x14, 0x52, 0x49, 0x5B],
            [0xB1, 0x29, 0x3B, 0x33, 0x05, 0x41, 0x85, 0x92, 0xD2, 0x10,
             0xD2, 0x32, 0xC6, 0x42, 0x9B, 0x69],
            [0xBD, 0x3D, 0xC2, 0x87, 0xB8, 0x7C, 0x47, 0x15, 0x6A, 0x6C,
             0x95, 0x27, 0xAC, 0x2E, 0x0E, 0x4E],
            [0xCC, 0x96, 0xED, 0x16, 0x74, 0xEA, 0xAA, 0x03, 0x1E, 0x86,
             0x3F, 0x24, 0xB2, 0xA8, 0x31, 0x6A],
            [0x8E, 0x51, 0xEF, 0x21, 0xFA, 0xBB, 0x45, 0x22, 0xE4, 0x3D,
             0x7A, 0x06, 0x56, 0x95, 0x4B, 0x6C],
            [0xBF, 0xE2, 0xBF, 0x90, 0x45, 0x59, 0xFA, 0xB2, 0xA1, 0x64,
             0x80, 0xB4, 0xF7, 0xF1, 0xCB, 0xD8],
            [0x28, 0xFD, 0xDE, 0xF8, 0x6D, 0xA4, 0x24, 0x4A, 0xCC, 0xC0,
             0xA4, 0xFE, 0x3B, 0x31, 0x6F, 0x26]]
        self.maxDiff = None
        self.assertEqual(expanded, keyexpansion11(key))

    def test_keyexpansion11_FIPS(self):
        key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7,
               0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]
        keyexpansion = [
            [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7,
             0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c],
            [0xa0, 0xfa, 0xfe, 0x17, 0x88, 0x54, 0x2c, 0xb1, 0x23, 0xa3,
             0x39, 0x39, 0x2a, 0x6c, 0x76, 0x05],
            [0xf2, 0xc2, 0x95, 0xf2, 0x7a, 0x96, 0xb9, 0x43, 0x59, 0x35,
             0x80, 0x7a, 0x73, 0x59, 0xf6, 0x7f],
            [0x3d, 0x80, 0x47, 0x7d, 0x47, 0x16, 0xfe, 0x3e, 0x1e, 0x23,
             0x7e, 0x44, 0x6d, 0x7a, 0x88, 0x3b],
            [0xef, 0x44, 0xa5, 0x41, 0xa8, 0x52, 0x5b, 0x7f, 0xb6, 0x71,
             0x25, 0x3b, 0xdb, 0x0b, 0xad, 0x00],
            [0xd4, 0xd1, 0xc6, 0xf8, 0x7c, 0x83, 0x9d, 0x87, 0xca, 0xf2,
             0xb8, 0xbc, 0x11, 0xf9, 0x15, 0xbc],
            [0x6d, 0x88, 0xa3, 0x7a, 0x11, 0x0b, 0x3e, 0xfd, 0xdb, 0xf9,
             0x86, 0x41, 0xca, 0x00, 0x93, 0xfd],
            [0x4e, 0x54, 0xf7, 0x0e, 0x5f, 0x5f, 0xc9, 0xf3, 0x84, 0xa6,
             0x4f, 0xb2, 0x4e, 0xa6, 0xdc, 0x4f],
            [0xea, 0xd2, 0x73, 0x21, 0xb5, 0x8d, 0xba, 0xd2, 0x31, 0x2b,
             0xf5, 0x60, 0x7f, 0x8d, 0x29, 0x2f],
            [0xac, 0x77, 0x66, 0xf3, 0x19, 0xfa, 0xdc, 0x21, 0x28, 0xd1,
             0x29, 0x41, 0x57, 0x5c, 0x00, 0x6e],
            [0xd0, 0x14, 0xf9, 0xa8, 0xc9, 0xee, 0x25, 0x89, 0xe1, 0x3f,
             0x0c, 0xc8, 0xb6, 0x63, 0x0c, 0xa6]
        ]

        self.assertEqual(keyexpansion11(key), keyexpansion)


if __name__ == '__main__':
    unittest.main()
