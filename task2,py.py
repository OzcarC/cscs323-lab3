

# adapted code from https://en.wikipedia.org/wiki/SHA-1#SHA-1_pseudocode
def sha1(msg):
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    msg_len = len(msg)
    msg_in_chunks =