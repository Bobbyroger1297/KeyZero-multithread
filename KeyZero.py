import requests
from bit import Key
from time import sleep, time
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from multiprocessing import cpu_count

if not os.path.exists("cache.txt"):
    open("cache.txt", "w+").close()


class Btcbf():
    def __init__(self):
        self.start_t = 0
        self.prev_n = 0
        self.cur_n = 0
        self.start_n = 0
        self.end_n = 0
        self.seq = False
        self.privateKey = None
        self.start_r = 0
        self.cores = cpu_count()
        self.lock = threading.Lock()

        loaded_addresses = open("address.txt", "r").readlines()
        loaded_addresses = [x.rstrip() for x in loaded_addresses]
        loaded_addresses = [x for x in loaded_addresses if 'wallet' not in x and len(x) > 0]
        self.loaded_addresses = set(loaded_addresses)

    def speed(self):
        while True:
            if self.cur_n != 0:
                cur_t = time()
                n = self.cur_n
                if self.prev_n == 0:
                    self.prev_n = n
                elapsed_t = cur_t - self.start_t
                rate = abs(n - self.prev_n) // 2
                h = int(elapsed_t // 3600)
                m = int(elapsed_t // 60 % 60)
                s = int(elapsed_t % 60)
                print(
                    f"current n: {n}, rate: {rate}/s, "
                    f"elapsed: [{h:02}:{m:02}:{s:02}], "
                    f"total: {n - self.start_r}   ",
                    end="\r"
                )
                self.prev_n = n
                if self.seq:
                    open("cache.txt", "w").write(f"{self.cur_n}-{self.start_r}-{self.end_n}")
            sleep(2)

    def _save_found(self, address, wif):
        with self.lock:
            print(f"\nWow matching address found!!")
            print(f"Public Address: {address}")
            print(f"Private Key:    {wif}")
            with open("foundkey.txt", "a") as f:
                f.write(address + "\n")
                f.write(wif + "\n")

    def random_brute(self, n):
        with self.lock:
            self.cur_n = n
        key = Key()
        if key.address in self.loaded_addresses:
            self._save_found(key.address, key.to_wif())
            os._exit(0)

    def sequential_brute(self, n):
        with self.lock:
            self.cur_n = n
        key = Key.from_int(n)
        if key.address in self.loaded_addresses:
            self._save_found(key.address, key.to_wif())
            os._exit(0)

    def random_online_brute(self, n):
        with self.lock:
            self.cur_n = n
        key = Key()
        try:
            resp = requests.get(
                f"https://blockchain.info/q/getreceivedbyaddress/{key.address}/",
                timeout=10
            ).text
            if int(resp) > 0:
                self._save_found(key.address, key.to_wif())
                os._exit(0)
        except Exception:
            pass

    def num_of_cores(self):
        available_cores = cpu_count()
        cores = input(
            f"\nNumber of available cores: {available_cores}\n"
            f"How many cores to use? (leave empty for all)\n> "
        )
        if cores == "":
            self.cores = available_cores
        elif cores.isdigit():
            c = int(cores)
            if 0 < c <= available_cores:
                self.cores = c
            elif c <= 0:
                print(f"Invalid number of cores: {c}")
                exit()
            else:
                confirm = input(f"You only have {available_cores} cores. Use {c} anyway? [y/n] > ")
                self.cores = c if confirm == "y" else available_cores
        else:
            print("Invalid input.")
            exit()

    def _run_pool(self, target, iterable, delay=0):
        """Launch ThreadPoolExecutor with the configured core count."""
        with ThreadPoolExecutor(max_workers=self.cores) as pool:
            self.start_t = time()
            for i in iterable:
                pool.submit(target, i)
                if delay:
                    sleep(delay)

    def generate_random_address(self):
        key = Key()
        print(f"\nPublic Address: {key.address}")
        print(f"Private Key:    {key.to_wif()}")

    def generate_address_fromKey(self):
        if self.privateKey:
            key = Key(self.privateKey)
            print(f"\nPublic Address: {key.address}")
            print("\nYour wallet is ready!")
        else:
            print("No key entered.")

    def get_user_input(self):
        print("\nWhat do you want to do?")
        print("  [1]: Generate random key pair")
        print("  [2]: Generate public address from private key")
        print("  [3]: Brute force - offline mode")
        print("  [4]: Brute force - online mode")
        print("  [0]: Exit")
        user_input = input("\n> ")

        if user_input == "1":
            self.generate_random_address()
            print("\nYour wallet is ready!")
            input("\nPress Enter to exit")
            exit()

        elif user_input == "2":
            self.privateKey = input("\nEnter Private Key > ")
            try:
                self.generate_address_fromKey()
            except Exception:
                print("\nIncorrect key format")
            input("Press Enter to exit")
            exit()

        elif user_input == "3":
            method = input("\n  [1]: Random attack\n  [2]: Sequential attack\n  [0]: Exit\n\n> ")
            self.num_of_cores()

            if method == "1":
                print("\nStarting random offline attack...")
                self.start_n = 0
                self._run_pool(self.random_brute, range(10**17))

            elif method == "2":
                cache = open("cache.txt", "r").read().strip()
                if cache:
                    r0 = cache.split("-")
                    start, origin, end = int(r0[0]), int(r0[1]), int(r0[2])
                    print(f"Resuming range {start}-{end}")
                    self.start_r = origin
                    self.start_n = start
                    self.end_n = end
                    self.seq = True
                    self._run_pool(self.sequential_brute, range(start, end))
                else:
                    range0 = input("\nEnter range in decimals (e.g. 1-1000000) > ")
                    r0 = range0.split("-")
                    start, end = int(r0[0]), int(r0[1])
                    open("cache.txt", "w").write(f"{start}-{start}-{end}")
                    self.start_r = start
                    self.start_n = start
                    self.end_n = end
                    self.seq = True
                    print("\nStarting sequential offline attack...")
                    self._run_pool(self.sequential_brute, range(start, end))
            else:
                exit()

        elif user_input == "4":
            method = input("\n  [1]: Random attack\n  [0]: Exit\n\n> ")
            self.num_of_cores()

            if method == "1":
                print("\nStarting random online attack...")
                self.start_n = 0
                # throttle to avoid API bans
                self._run_pool(self.random_online_brute, range(10**17), delay=0.1)
            else:
                exit()

        elif user_input == "0":
            print("Exiting...")
            sleep(1)
            exit()
        else:
            print("Invalid input, exiting.")
            exit()


if __name__ == "__main__":
    obj = Btcbf()
    t_speed = threading.Thread(target=obj.speed, daemon=True)
    t_speed.start()
    try:
        obj.get_user_input()
    except KeyboardInterrupt:
        print("\n\nCtrl+C pressed. Exiting...")
        exit()
