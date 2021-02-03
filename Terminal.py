import argparse
import hashlib
from AES_128_Implementation import aes_encrypt, aes_decrypt

parser = argparse.ArgumentParser(description='Encrypt and decrypt a string contained in a file, using a password that '
                                             'is also contained in that file')
parser.add_argument('input', type=str,
                    help='Directory of the input file')
parser.add_argument('output', type=str,
                    help='Directory of output file')
parser.add_argument('password', type=str,
                    help='Password used in the cypher')
parser.add_argument('-e', '--encrypt', action="store_true",
                    help='encrypt the input file')
parser.add_argument('-d', '--decrypt', action="store_true",
                    help='decrypt the input file')
args = parser.parse_args()

if args.encrypt and args.decrypt:
    print('Please only use one of the arguments: -e or -d.')
if not args.encrypt and not args.decrypt:
    print('Please use one of the arguments: -e or -d.')

hash = hashlib.shake_128(args.password.encode()).digest(128)
with open(args.input, 'br') as input, open(args.output, 'bw') as output:
    read_data = input.read(16)
    while read_data != b'':
        if len(read_data) < 16:
            read_data = read_data.ljust(16,b' ')
        if args.encrypt:
            output.write(bytes(aes_encrypt(read_data, hash)))
        if args.decrypt:
            output.write(bytes(aes_decrypt(read_data, hash)))
        read_data = input.read(16)

print(args)
print(hash)
