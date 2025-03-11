import requests
import time
import numpy as np

url = "http://127.0.0.1:8080/"
run_times = 30

max_time = -1
h_str = "00"*20
max_guess = ["" for i in range(20)]

for j in range(20):
    print(max_guess)
    alt_guesses = []
    max_time = -1
    for i in range(256):
        guess_byte = hex(i)[2:].zfill(2)
        guess = ''.join(max_guess[:j]) + guess_byte + "00"*(20-(j+1))
        times = []
        for _ in range(run_times):
            st_t = time.perf_counter()
            r = requests.get(url+"?q=Message&mac="+guess)
            end_t = time.perf_counter()
            times.append(end_t-st_t)
        time_taken = np.median(times)

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
