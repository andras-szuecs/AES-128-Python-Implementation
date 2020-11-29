
key = [61, 20, 224, 15, 10, 78, 29, 58, 245, 44, 85, 182, 255, 36, 120, 204]

def keyexpansioncore(key):
    rotated_key = key[1:] + key[:1]
    sub_key = []
    for i in rotated_key:
        sub_key.append(sbox[i])

    return sub_key   

def gen_next_key(key):
    nextkey = []
    for i in range(0,len(key),4):
        nextkey += keyexpansioncore(key[i:i+4])
    return nextkey

def keyexpansion11(key):
    keys = [key]
    for i in range(10):
        key = gen_next_key(key)
        keys.append(key)
    return keys    
