def printhex(list, label=''):
    """prints a list in hex format """
    print(label, "[", end='')
    for i in list:
        print(hex(i), end=', ')
    print("]")

def str_to_block(block_str):
    """converts hex string to list with hex numbers"""
    print(["0x" + block_str[i:i + 2] for i in range(0, 32, 2)])
    block_vector = [int(block_str[i:i + 2], 16) for i in range(0, 32, 2)]
    printhex([block_vector[c * 4 + r] for c in range(0, 4) for r in range(0, 4)])
