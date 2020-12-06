from key_expansion import keyexpansion11
from rounds import *


def aes_encrypt(plaintext, key):
    """Encrypts a 128 bit plaintext with a 128 bit key to get an output of 128 bit ciphertext. Is the equivalent of
    the AES in ECB mode, encrypting 1 block """
    keys = keyexpansion11(key)
    ciphertext = AddRoundKey(plaintext, keys[0])
    for i in range(1, 10):
        round_key = keys[i]
        ciphertext = aes_encrypt_round(ciphertext, round_key, str(i))
    round_key = keys[10]
    ciphertext = aes_encrypt_round_final(ciphertext, round_key)
    return ciphertext


def aes_decrypt(ciphertext, key):
    """Decrypts a 128 bit ciphertext with a 128 bit key to get an output of 128 bit plaintext. Is the equivalent of
    the AES in ECB mode, decrypting 1 block """
    keys = keyexpansion11(key)
    round_key = keys[10]
    ciphertext = aes_decrypt_round_first(ciphertext, round_key)
    for i in range(9, 0, -1):
        round_key = keys[i]
        ciphertext = aes_decrypt_round(ciphertext, round_key)
    round_key = keys[0]
    plaintext = AddRoundKey(ciphertext, round_key)
    return plaintext


class TestStringMethods(unittest.TestCase):
    def test_AES(self):
        key = [0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf]
        plaintext = bytearray(
            [0x0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        expected_cyphertext = [0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x4, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5,
                               0x5a]
        cyphertext = aes_encrypt(plaintext, key)
        self.assertEqual(expected_cyphertext, cyphertext)

    def test_AES_roundtrip(self):
        key = [0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf]
        plaintext = bytearray(
            [0x0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        cyphertext = aes_encrypt(plaintext, key)
        self.assertEqual(bytearray(aes_decrypt(cyphertext, key)), plaintext)


if __name__ == '__main__':
    unittest.main()
