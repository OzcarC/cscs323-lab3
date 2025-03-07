import requests
import time

url = "http://localhost:8080/"

max_time = -1
h_str = "00"*20
max_guess = ["" for i in range(20)]

possible = 2
for j in range(20):
    print(max_guess)
    alt_guesses = []
    max_time = -1
    for i in range(256):
        guess_byte = hex(i)[2:].zfill(2)
        guess = ''.join(max_guess[:j]) + guess_byte + "00"*(20-(j+1))
        timestamp = str(time.time())
        st_t = time.time()
        r = requests.get(url+"?q=IHATEYOUIHATEYOU&time="+timestamp+"&mac="+guess)
        end_t = time.time()
        time_taken = end_t - st_t

        if time_taken > max_time:
            if max_guess[j] != '':
                alt_guesses.append((max_guess[j], max_time))
            max_time = time_taken
            max_guess[j] = guess_byte
    alt_guesses.append((max_guess[j], max_time))
    alt_guesses.sort(key=lambda x: x[1], reverse=True)
    print(alt_guesses)


max_guess = ''.join(max_guess)
print(max_guess)


