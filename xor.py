
def xor(inp, key):
    return bytes(a^b for a,b in zip(inp,key))