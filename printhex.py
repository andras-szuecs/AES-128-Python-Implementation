def printhex(l):
    print("[", end='')
    for i in l:
        print(hex(i), end=', ')
    print("]")