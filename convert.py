import base64

def byteToHex(byte):
    bits = hex(int(byte,2))[2:]
    if len(byte)/4 > len(bits):
        lead_zero = '0'* ((len(byte)-(len(bits)*4))//4)
        bits = lead_zero+bits
    return bits

def hexToByte(hex):
    ans = ""
    for i in range(0,(len(hex)),2):
        try:
            temp = bin(int(hex[i:i+2],16))[2:].zfill(8)
        except ValueError:
            temp = ""
        else:
            ans += temp
    return ans

def hexToInt(hex):
    return int(hex,16)
def b64ToBin(inp):
    dec = base64.b64decode(inp)
    dec = "".join(["{:08b}".format(x) for x in dec])
    return dec

def hexToAscii(hex):
    if len(hex) == 1:
        hex = hex.rjust(2,"0")
    return bytes.fromhex(hex).decode('utf-8')

def stringToHex(inp):
    return inp.encode('utf-8').hex()

def intToB64(inp):

    enc=base64.b64encode(str(inp).encode())
    return enc

def strToBin(text):
    bin = ''.join(format(ord(char),'08b') for char in text)
    return bin

def bytesToBin(text):
    return bin(int.from_bytes(text))