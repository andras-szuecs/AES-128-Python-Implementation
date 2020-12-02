from key_expansion import keyexpansion11
from rounds import *


def aes_encrypt(plaintext, key):
    keys = keyexpansion11(key)
    cyphertext = AddRoundKey(plaintext, keys[0])
    for i in range(1, 10):
        round_key = keys[i]
        cyphertext = aes_encrypt_round(cyphertext, round_key)
    round_key = keys[10]
    cyphertext = aes_encrypt_round_final(cyphertext, round_key)
    return cyphertext


def aes_decrypt(cyphertext, key):
    keys = keyexpansion11(key)
    round_key = keys[10]
    cyphertext = aes_decrypt_round_first(cyphertext, round_key)
    for i in range(9, 0, -1):
        round_key = keys[i]
        cyphertext = aes_decrypt_round(cyphertext, round_key)
    round_key = keys[0]
    plaintext = AddRoundKey(cyphertext, round_key)
    return plaintext



class TestStringMethods(unittest.TestCase):
    def test_AES_ECB(self):
        key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]
        plaintext = bytearray(
            [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a])
        cyphertext = aes_encrypt(plaintext, key)
        decrypted_plaintext = aes_decrypt(cyphertext, key)
        self.assertEqual(plaintext,bytearray(decrypted_plaintext))


if __name__ == '__main__':
    unittest.main()
