import hashlib, os, random, sys


def popcount(x):
    x -= (x >> 1) & 0x5555555555555555
    x = (x & 0x3333333333333333) + ((x >> 2) & 0x3333333333333333)
    x = (x + (x >> 4)) & 0x0f0f0f0f0f0f0f0f
    return ((x * 0x0101010101010101) & 0xffffffffffffffff ) >> 56


def format_hash_bin(h):
    s = len(h)
    return bin(int.from_bytes(h, byteorder='big'))[2:].rjust(s*8, '0')

def format_hash_hex(h):
    s = len(h)
    return hex(int.from_bytes(h, byteorder='big'))[2:].rjust(s * 2, '0')

def print_hash_bin(h):
    print(format_hash_bin(h))

def print_hash_hex(h):
    print(format_hash_hex(h))



def bit_from_bytes(h, idx):
    return (int.from_bytes(h, byteorder='big') >> idx) & 1


def xor_binary_string(b1, b2):
    size = max(len(b1),len(b2))
    result = bytearray(b'\x00'*size)
    for i in range(size):
        result[i] = b1[i] ^ b2[i]
    return bytes(result)


class HashBreaker:
    def __init__(self):
        self.lut = 256*[None]

    def hash(self, value):
        if not isinstance(value, bytes):
            raise TypeError('Value for hash must be in bytes')
        m = hashlib.sha256()
        m.update(value)
        hashval = m.digest()
        return hashval


    def xor_hash(self, list):
        result = b'\x00'*32
        for plaintext in list:
            result = xor_binary_string(result, self.hash(plaintext))
        return result

    def reduce_inputs(self, inputs):
        inputs.sort()
        occurence = 0
        prev = None
        new_list = []
        for value in inputs:
            if prev == value:
                occurence += 1
            else:
                if (prev is not None) and (occurence % 2):
                    new_list.append(prev)
                prev = value
                occurence = 1
        if len(inputs) and occurence % 2:
            new_list.append(inputs[-1])
        return new_list

    def generateLUT(self):
        for i in range(256):
            found_good_candidate = False
            while not found_good_candidate:
                candidate = os.urandom(32)
                hash_sum = self.hash(candidate)
                self.lut[i] = {'hash': None, 'inputs':[candidate]}
                for j in range(i):
                    if bit_from_bytes(hash_sum, j) != 0:
                        self.lut[i]['inputs'].extend(self.lut[j]['inputs'])
                self.lut[i]['inputs'] = self.reduce_inputs(self.lut[i]['inputs'])
                hash_sum = self.xor_hash(self.lut[i]['inputs'])
                if bit_from_bytes(hash_sum, i) == 0:
                    # Candidate NOT usable
                    continue
                else:
                    found_good_candidate = True
                self.lut[i]['hash'] = hash_sum


                for j in range(i):
                    if  bit_from_bytes(self.lut[j]['hash'], i) != 0:
                        self.lut[j]['inputs'].extend(self.lut[i]['inputs'])
                        self.lut[j]['inputs'] = self.reduce_inputs(self.lut[j]['inputs'])
                        self.lut[j]['hash'] = xor_binary_string(self.lut[j]['hash'], self.lut[i]['hash'])

    def fakeHash(self, wanted_hash):
        if not isinstance(wanted_hash, bytes):
            raise TypeError('wanted_hash must be in bytes')
        if len(wanted_hash) != 32:
            raise ValueError('wanted_hash must be a 256 Bit hash (32 bytes)')
        inputs = []
        for i in range(256):
            if bit_from_bytes(wanted_hash, i) != 0:
                inputs.extend(self.lut[i]['inputs'])
        inputs = self.reduce_inputs(inputs)
        return inputs

    def alterHash(self, previous_hash, wanted_hash):
        diff = xor_binary_string(previous_hash, wanted_hash)
        return self.fakeHash(diff)



def main():
    if len(sys.argv) < 2:
        print("Usage: "+sys.argv[0]+" [wantedHash] [previousHash]\nCalculates files as input in a 'xor-hash' using sha256 that results in the wanted hash.\nsecond argument is optional if you want to alter a given hash to another one.")
        exit(1)

    hb = HashBreaker()
    hb.generateLUT()

    wanted_hash = bytes.fromhex(sys.argv[1])
    if len(sys.argv) == 2:
        inputs = hb.fakeHash(wanted_hash)
    else:
        previous_hash = bytes.fromhex(sys.argv[2t])
        inputs = hb.alterHash(previous_hash, wanted_hash)

    print("To get the wanted hash you need to add the following files:")
    for entry in inputs:
        print_hash_hex(entry)

if __name__ == '__main__':
    main()

