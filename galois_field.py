import unittest

def MM(c, m):
    output = []
    for i in m:
        output.append(GF(i[0], c[0]) ^ GF(i[1], c[1]) ^ GF(i[2], c[2]) ^ GF(i[3], c[3]))
    return output

def GF(a, b):
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
        self.assertEqual(0xb3, GF(0xd4, 2))

    def test_gf_mul_by_3(self):
        self.assertEqual(0xda, GF(0xbf, 3))

    def test_mm(self):
        columns = [0xd4, 0xbf, 0x5d, 0x30]
        Matrix = [
            [2,3,1,1],
            [1,2,3,1],
            [1,1,2,3],
            [3,1,1,2]
        ]
        self.assertEqual([0x04, 0x66, 0x81, 0xe5], MM(columns,Matrix))

if __name__ == '__main__':
    unittest.main()
