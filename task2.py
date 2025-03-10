import convert
import random
import string

# adapted code from https://en.wikipedia.org/wiki/SHA-1#SHA-1_pseudocode
def l_rotate(num, rot):
    return ((num << rot) | (num >> (32-rot))) & 0xFFFFFFFF

def sha1(msg):
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    #preprocessing
    msg_len = len(msg)*8
    msg_len_bin = bin(msg_len)[2:].zfill(64)
    msg_bin = convert.strToBin(msg)
    msg_bin += "1"
    zeros = 448 - ((msg_len+1) % 512)
    msg_bin += "0"*zeros
    msg_bin += msg_len_bin

    #chunks
    chunks = []
    for i in range(0,msg_len,512):
        chunks.append(msg_bin[i:i+512])
    for chunk in chunks:
        words = []
        for i in range(16):
            words.append(chunk[i*32:(i+1)*32])
        for i in range(16,80):
            temp = l_rotate((int(words[i-3],2) ^ int(words[i-8],2) ^ int(words[i-14],2) ^ int(words[i-16],2)),1)
            words.append(bin(temp)[2:].zfill(32))

        #initialize hash vals for chunk
        a,b,c,d,e = h0,h1,h2,h3,h4

        #main loop
        for i in range(80):
            if 0 <= i <= 19:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            elif 60 <= i <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (l_rotate(a,5) + f + e + k + int(words[i],2) & 0xFFFFFFFF)
            e = d
            d = c
            c = l_rotate(b,30)
            b = a
            a = temp

        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF

    hh = (h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4
    return hh

def rand_str(length):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

hashtable = {}


while True:
    msg = rand_str(36)
    hash = bin(sha1(msg))[2:52]
    # hash = bin(int(hashlib.sha1(msg.encode()).hexdigest(), 16))[2:].zfill(160)[:40]
    # print(f"H({msg}) = {hash}")
    if hash in hashtable:
        print(f"Collisions:\n{hashtable[hash]}: {bin(sha1(hashtable[hash]))}\n{msg}: {bin(sha1(msg))}")
        break
    else:
        hashtable[hash] = msg