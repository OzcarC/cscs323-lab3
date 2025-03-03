import requests
from bs4 import BeautifulSoup
from xor import xor
from collections import deque
def getValidC():
    r = requests.get("http://127.0.0.1:8080/eavesdrop")
    soup = BeautifulSoup(r.content, "html.parser")
    tk = str([x.string for x in soup.find_all("font")][1])
    return tk


c = getValidC().strip(" ")

# split up c
iv_h = c[:32]
c1_h = c[32:64]
c2_h = c[64:96]
c3_h = c[96:]

# m1 padding
decrypted_block = deque([])
iv_b = bytearray(bytes.fromhex(iv_h))
c1_b = bytes.fromhex(c1_h)
padding = 0
prev = iv_b
for i in range(15, 0, -1):
    padding += 1
    for guess in range(0,256):
        iv_b[i] = (iv_b[i] + 1) % 256
        joined = iv_b.hex() + c1_b.hex()
        url = f"http://127.0.0.1:8080/?enc={joined}"
        if requests.get(url).status_code == 404:
            decrypted_block.appendleft(xor(xor(iv_b[i], padding), prev[i]))
            iv_b[i:] = [(x+1)%256 for x in iv_b[i:]]
            break
    # if len(correct_guesses) <= i:
    #     break
correct_guesses = list(correct_guesses)
print (correct_guesses)