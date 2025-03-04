import requests
from bs4 import BeautifulSoup
from xor import xor
from collections import deque
def getValidC():
    r = requests.get("http://127.0.0.1:8080/eavesdrop")
    soup = BeautifulSoup(r.content, "html.parser")
    tk = str([x.string for x in soup.find_all("font")][1])
    return tk


def oracle(ct:bytes):
    ct_h = ct.hex()
    return requests.get(f"http://127.0.0.1:8080/?enc={ct_h}").status_code == 404


# Adapted code from https://github.com/flast101/padding-oracle-attack-explained by flast101
def paddingOracleAttack(ct):
    block_num = len(ct)//16
    msg = bytes()
    for i in range(block_num,0,-1):
        curr_ct_block = ct[(i-1)*16:i*16]
        if (i==1):
            prev_ct_block = bytearray(ct[0:16]) #the first 16 bytes are the IV
        else:
            prev_ct_block = ct[(i-2)*16:(i-1)*16]
        guess_block = prev_ct_block
        curr_msg_block = bytearray(ct[0:16])
        padding = 0
        for j in range(16,0, -1):
            padding+=1
            for val in range(0,256):
                guess_block = bytearray(guess_block)
                guess_block[j-1] = (guess_block[j-1]+1)%256
                joined_ct_block = bytes(guess_block)+curr_ct_block
                if(oracle(joined_ct_block)):
                    curr_msg_block[-padding] = guess_block[-padding] ^ prev_ct_block[-padding] ^ padding
                    for k in range(1, padding+1):
                        guess_block[-k] = padding+1 ^ curr_msg_block[-k] ^ prev_ct_block[-k]
                    break
        msg = bytes(curr_msg_block) + bytes(msg)
    return msg[16:-msg[-1]]





c = getValidC()
c = bytes.fromhex(c)
print(c)

out = paddingOracleAttack(c)
print(out)
