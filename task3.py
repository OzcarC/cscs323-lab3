import convert
import urllib.parse
import requests
from xor import xor
def l_rotate(num, rot):
    return ((num << rot) | (num >> (32-rot))) & 0xFFFFFFFF

def sha1_mod(hash, msg, length):
    h0 = (hash >> 128) & 0xFFFFFFFF
    h1 = (hash >> 96) & 0xFFFFFFFF
    h2 = (hash >> 64) & 0xFFFFFFFF
    h3 = (hash >> 32) & 0xFFFFFFFF
    h4 = hash & 0xFFFFFFFF

    # preprocessing
    msg_len = length
    msg_len_bin = bin(msg_len)[2:].zfill(64)
    msg_bin = bin(int.from_bytes(msg, "big"))[2:].zfill(len(msg)*8)
    msg_bin += "1"
    zeros = 448 - ((msg_len + 1) % 512)
    msg_bin += "0" * zeros
    msg_bin += msg_len_bin

    # chunks
    chunks = []
    for i in range(0, len(msg_bin), 512):
        chunks.append(msg_bin[i:i + 512])
    for chunk in chunks:
        words = []
        for i in range(16):
            words.append(chunk[i * 32:(i + 1) * 32])
        for i in range(16, 80):
            temp = l_rotate(
                (int(words[i - 3], 2) ^ int(words[i - 8], 2) ^ int(words[i - 14], 2) ^ int(words[i - 16], 2)), 1)
            words.append(bin(temp)[2:].zfill(32))

        # initialize hash vals for chunk
        a, b, c, d, e = h0, h1, h2, h3, h4

        # main loop
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

            temp = (l_rotate(a, 5) + f + e + k + int(words[i], 2) & 0xFFFFFFFF)
            e = d
            d = c
            c = l_rotate(b, 30)
            b = a
            a = temp

        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF

    hh = (h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4
    return hh

def add_padding(msg):
    msg_len = len(msg) * 8
    msg_len_bin = bin(msg_len)[2:].zfill(64)
    msg_bin = convert.strToBin(msg)
    msg_bin += "1"
    zeros = 448 - ((msg_len + 1) % 512)
    msg_bin += "0" * zeros
    msg_bin += msg_len_bin

    n = int(msg_bin,2)
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return b

# url = "http://127.0.0.1:8080/"
#
# msg = input("Enter a message: ")
# h1 = int(input("Enter it's hash: "),16)
#
# for i in range(33):
#     padded = add_padding("a"*i +msg)
#     forged_message = b'Hello'
#
#     h2 = sha1_mod(h1,forged_message, len(padded)*8+len(forged_message)*8)
#
#     final_msg = padded[i:]+forged_message
#
#     url_string = urllib.parse.quote_from_bytes(final_msg)
#
#     headers = {
#         'who':"Abbott",
#         'what':url_string,
#         'mac':hex(h2)[2:]
#     }
#
#     r = requests.post(url, data=headers)
#



#HMAC

def sha1(msg):
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    #preprocessing
    msg_len = len(msg)*8
    msg_len_bin = bin(msg_len)[2:].zfill(64)
    if isinstance(msg, str):
        msg_bin = convert.strToBin(msg)
    elif isinstance(msg, bytes):
        msg_bin = bin(int.from_bytes(msg, "big"))[2:].zfill(len(msg) * 8)
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


def hmac(key:bytes, msg:bytes, blockSize:int, outputSize:int):
    block_sized_key = computeBlockSizedKey(key,blockSize,outputSize)
    o_key_pad = xor(block_sized_key, b"\x5c"*blockSize)
    i_key_pad = xor(block_sized_key, b"\x36"*blockSize)
    return sha1(o_key_pad + sha1(i_key_pad+msg).to_bytes(outputSize,'big'))

def computeBlockSizedKey(key:bytes, blockSize:int, outputSize:int):
    if len(key) > blockSize:
        key = int.to_bytes(sha1(key), outputSize, 'big') + b'\x00'*(blockSize-outputSize)

    elif len(key) < blockSize:
        return key+b"\x00"*(blockSize-len(key))

    return key

key = b'\xaa'*80
msg = b'Test Using Larger Than Block-Size Key - Hash Key First'

res = hmac(b'Jefe', b'what do ya want for nothing?', 64, 20)

print(hex(res))


res = hmac(key,msg,64,20)
print(hex(res))