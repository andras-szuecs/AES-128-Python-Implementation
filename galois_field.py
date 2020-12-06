import unittest


def MatrixMultiply(c, m):
    """Multiplies the elements of 2 matrices, using finite field
    multiplication"""
    output = []
    for i in m:
        output.append(
            GFMultiply(i[0], c[0]) ^ GFMultiply(i[1], c[1]) ^ GFMultiply(
                i[2], c[2]) ^ GFMultiply(i[3], c[3]))
    return output


def GFMultiply(a, b):
    """Rijndaels Finite field multiplication (GF(2^8)) for any 2 numbers"""
    p = 0
    for i in range(8):
        if a == 0 or b == 0:
            break
        if b & 0x01 == 0x01:
            p = p ^ a
        b = b >> 1
        carry = a & 0x80
        a = a << 1
        a = a & 0xFF
        if carry == 0x80:
            a = a ^ 0x1B
    return p


class TestStringMethods(unittest.TestCase):

    def test_gf_mul_by_2(self):
        self.assertEqual(0xb3, GFMultiply(0xd4, 2))

    def test_gf_mul_by_3(self):
        self.assertEqual(0xda, GFMultiply(0xbf, 3))

    def test_mm(self):
        columns = [0xd4, 0xbf, 0x5d, 0x30]
        Matrix = [
            [2, 3, 1, 1],
            [1, 2, 3, 1],
            [1, 1, 2, 3],
            [3, 1, 1, 2]
        ]
        self.assertEqual([0x04, 0x66, 0x81, 0xe5],
                         MatrixMultiply(columns, Matrix))


if __name__ == '__main__':
    unittest.main()
