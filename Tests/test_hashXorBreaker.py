import unittest, math
import hashXorBreaker


class Test_hashXorBreaker(unittest.TestCase):
    def test_format_hash_bin(self):
        self.assertEqual(hashXorBreaker.format_hash_bin(b'\xde\xad\xbe\xef'), '11011110101011011011111011101111')
        self.assertEqual(hashXorBreaker.format_hash_bin(b'\x3f'), '00111111')
        self.assertEqual(hashXorBreaker.format_hash_bin(b'\xbc\xf4\x7b\x3b\x3f\xf8\x30\x09\xc8\xb0\xda\x6b\x21\x65\x11\x6d'), '10111100111101000111101100111011001111111111100000110000000010011100100010110000110110100110101100100001011001010001000101101101')
    def test_popcount(self):
        self.assertEqual(hashXorBreaker.popcount(1), 1)
        self.assertEqual(hashXorBreaker.popcount(0b101010), 3)
    def test_bit_from_bytes(self):
        for i in range(8):
            self.assertEqual(hashXorBreaker.bit_from_bytes(b'\xff', i), 1)
        self.assertEqual(hashXorBreaker.bit_from_bytes(b'\xff', 8), 0)
        # 0xdeadbeef = 0b11011110101011011011111011101111
        for i in range(32):
            self.assertEqual(hashXorBreaker.bit_from_bytes(b'\xde\xad\xbe\xef', i), [1,1,0,1,1,1,1,0,1,0,1,0,1,1,0,1,1,0,1,1,1,1,1,0,1,1,1,0,1,1,1,1][31-i])
        self.assertEqual(hashXorBreaker.bit_from_bytes(b'\xde\xad\xbe\xef', 4), 0)
        self.assertEqual(hashXorBreaker.bit_from_bytes(b'\xde\xad\xbe\xef', 31), 1)

    def test_xor_binary_string(self):
        self.assertEqual(hashXorBreaker.xor_binary_string(b'\xff', b'\xff'), b'\x00')
        self.assertEqual(hashXorBreaker.xor_binary_string(0x098f6bcd4621d373cade4e832627b4f6.to_bytes(16, byteorder='big'), 0xaadce520e20c2899f4ced228a79a3083.to_bytes(16, byteorder='big')), 0xa3538eeda42dfbea3e109cab81bd8475.to_bytes(16, byteorder='big'))
    def test_hash(self):
        obj = hashXorBreaker.HashBreaker()
        self.assertEqual(obj.hash(b'test'), 0x9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08.to_bytes(32, byteorder='big'))
    def test_xor_hash(self):
        same_values = [b'test', b'test']
        obj = hashXorBreaker.HashBreaker()
        self.assertEqual(obj.xor_hash(same_values), b'\x00'*32)
        different_values = [b'abc_ awd123', b'asdfghgbhhvu jkl', b'nudelsuppe']
        self.assertEqual(obj.xor_hash(different_values), 0xf6859513ec94e35bf19d9be10d7968e58eca0800217f8b2d63cbee13e500e0cb.to_bytes(32, byteorder='big'))
    def test_generateLUT(self):
        obj = hashXorBreaker.HashBreaker()
        obj.generateLUT()
        for i in range(len(obj.lut)):
            self.assertEqual(math.log2(int.from_bytes(obj.lut[i]['hash'], byteorder='big')), i)

if __name__ == '__main__':
    Test_hashXorBreaker()
