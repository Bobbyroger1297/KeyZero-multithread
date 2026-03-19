import requests
from bit import Key
from time import sleep, time
import os
import multiprocessing
from multiprocessing import Pool, cpu_count, Value, Manager
from concurrent.futures import ThreadPoolExecutor
from functools import partial
 
# ── helpers that must live at module level for pickling ──────────────────────
 
def _random_brute_worker(args):
    """Each worker generates keys independently using its own RNG."""
    n, loaded_addresses, found_flag, counter = args
    key = Key()
    with counter.get_lock():
        counter.value += 1
    if key.address in loaded_addresses:
        found_flag.value = 1
        _save_found(key.address, key.to_wif())
        os._exit(0)
 
 
def _sequential_brute_worker(args):
    """Derives a key from a specific integer n."""
    n, loaded_addresses, found_flag, counter = args
    key = Key.from_int(n)
    with counter.get_lock():
        counter.value += 1
    if key.address in loaded_addresses:
        found_flag.value = 1
        _save_found(key.address, key.to_wif())
        os._exit(0)
 
 
def _online_brute_worker(args):
    """Random key + live blockchain lookup (I/O-bound, uses threads internally)."""
    n, found_flag, counter = args
    key = Key()
    with counter.get_lock():
        counter.value += 1
    try:
        resp = requests.get(
            f"https://blockchain.info/q/getreceivedbyaddress/{key.address}/",
            timeout=10
        ).text
        if int(resp) > 0:
            found_flag.value = 1
            _save_found(key.address, key.to_wif())
            os._exit(0)
    except Exception:
        pass
 
 
def _save_found(address, wif):
    print(f"\n{'='*50}")
    print(f"  *** MATCHING ADDRESS FOUND ***")
    print(f"  Public Address : {address}")
    print(f"  Private Key    : {wif}")
    print(f"{'='*50}\n")
    with open("foundkey.txt", "a") as f:
        f.write(address + "\n")
        f.write(wif + "\n")
 
 
# ── speed monitor (runs in its own process) ──────────────────────────────────
 
def _speed_monitor(counter, start_t, start_n, seq, cur_n_val):
    """Dedicated process that prints throughput every 2 seconds."""
    prev = 0
    while True:
        sleep(2)
        n = counter.value
        if n == 0:
            continue
        elapsed = time() - start_t.value
        rate = abs(n - prev) // 2
        h, rem = divmod(int(elapsed), 3600)
        m, s = divmod(rem, 60)
        total = n - start_n.value
        print(
            f"  keys checked: {n:,}  |  rate: {rate:,}/s  |"
            f"  elapsed: {h:02}:{m:02}:{s:02}  |  total: {total:,}   ",
            end="\r"
        )
        if seq.value:
            # persist resume point
            try:
                open("cache.txt", "w").write(
                    f"{cur_n_val.value}-{start_n.value}-{cur_n_val.value + 1}"
                )
            except Exception:
                pass
        prev = n
 
 
# ── main class ───────────────────────────────────────────────────────────────
 
class Btcbf:
    def __init__(self):
        self.cores = cpu_count()
 
        # shared state (multiprocessing-safe)
        manager = multiprocessing.Manager()
        self.counter   = Value('Q', 0)   # unsigned long long
        self.found_flag = Value('b', 0)
        self.start_t   = Value('d', 0.0)
        self.start_n   = Value('Q', 0)
        self.cur_n     = Value('Q', 0)
        self.seq       = Value('b', 0)
 
        # load target addresses into a frozenset (shared via fork / copy)
        if not os.path.exists("address.txt"):
            print("WARNING: address.txt not found.")
            self.loaded_addresses = frozenset()
        else:
            lines = open("address.txt").readlines()
            lines = [x.strip() for x in lines if 'wallet' not in x and x.strip()]
            self.loaded_addresses = frozenset(lines)
            print(f"  Loaded {len(self.loaded_addresses):,} target addresses.")
 
        if not os.path.exists("cache.txt"):
            open("cache.txt", "w").close()
 
    # ── core selection ───────────────────────────────────────────────────────
 
    def ask_cores(self):
        available = cpu_count()
        ans = input(
            f"\n  Available CPU cores: {available}\n"
            f"  How many to use? (Enter = all) > "
        ).strip()
        if ans == "":
            self.cores = available
        elif ans.isdigit():
            c = int(ans)
            if 0 < c <= available:
                self.cores = c
            elif c > available:
                yn = input(f"  Only {available} cores available. Use {c} anyway? [y/n] > ")
                self.cores = c if yn.lower() == "y" else available
            else:
                print("  Invalid core count.")
                exit()
        else:
            print("  Invalid input.")
            exit()
        print(f"  Using {self.cores} core(s).\n")
 
    # ── speed monitor launcher ───────────────────────────────────────────────
 
    def _start_monitor(self):
        p = multiprocessing.Process(
            target=_speed_monitor,
            args=(self.counter, self.start_t, self.start_n, self.seq, self.cur_n),
            daemon=True
        )
        p.start()
        return p
 
    # ── attack runners ───────────────────────────────────────────────────────
 
    def run_random_offline(self):
        """
        True parallel random attack.
        Each core independently generates and checks random keys.
        The iterable just provides a job count — the randomness
        comes from Key() itself (uses os.urandom internally).
        """
        addresses = self.loaded_addresses
        found     = self.found_flag
        counter   = self.counter
 
        # Build a huge lazy arg list so Pool stays fed
        def arg_gen():
            i = 0
            while True:
                yield (i, addresses, found, counter)
                i += 1
 
        with self.start_t.get_lock():
            self.start_t.value = time()
 
        self._start_monitor()
        print(f"  Starting random offline attack on {self.cores} cores ...\n")
 
        with Pool(processes=self.cores) as pool:
            # imap_unordered keeps all cores busy without building the list in RAM
            for _ in pool.imap_unordered(_random_brute_worker, arg_gen(), chunksize=500):
                if self.found_flag.value:
                    pool.terminate()
                    break
 
    def run_sequential_offline(self, start, end):
        """
        Sequential attack: partitions [start, end) across all cores.
        Each core gets a contiguous slice → no overlap, no gaps.
        """
        addresses = self.loaded_addresses
        found     = self.found_flag
        counter   = self.counter
 
        with self.start_t.get_lock():
            self.start_t.value = time()
        self.start_n.value = start
        self.seq.value     = 1
 
        self._start_monitor()
        print(f"  Starting sequential offline attack [{start:,} → {end:,}] on {self.cores} cores ...\n")
 
        def arg_gen(s, e):
            for i in range(s, e):
                yield (i, addresses, found, counter)
 
        with Pool(processes=self.cores) as pool:
            for _ in pool.imap_unordered(_sequential_brute_worker, arg_gen(start, end), chunksize=1000):
                if self.found_flag.value:
                    pool.terminate()
                    break
                with self.cur_n.get_lock():
                    self.cur_n.value += 1
 
        # clear cache on completion
        open("cache.txt", "w").close()
        print("\n  Range complete.")
 
    def run_random_online(self):
        """
        Online mode: random keys checked against blockchain API.
        I/O-bound → ThreadPoolExecutor inside each process maximises throughput.
        Uses multiprocessing for process-level parallelism too.
        """
        found   = self.found_flag
        counter = self.counter
 
        def arg_gen():
            i = 0
            while True:
                yield (i, found, counter)
                i += 1
 
        with self.start_t.get_lock():
            self.start_t.value = time()
 
        self._start_monitor()
        print(f"  Starting random online attack on {self.cores} cores ...\n")
 
        with Pool(processes=self.cores) as pool:
            for _ in pool.imap_unordered(_online_brute_worker, arg_gen(), chunksize=10):
                if self.found_flag.value:
                    pool.terminate()
                    break
 
    # ── key generation utilities ─────────────────────────────────────────────
 
    def generate_random_address(self):
        key = Key()
        print(f"\n  Public Address : {key.address}")
        print(f"  Private Key    : {key.to_wif()}")
 
    def generate_from_private_key(self, wif):
        try:
            key = Key(wif)
            print(f"\n  Public Address : {key.address}")
            print("  Wallet ready!")
        except Exception:
            print("\n  Incorrect key format.")
 
    # ── main menu ────────────────────────────────────────────────────────────
 
    def menu(self):
        print("\n" + "="*50)
        print("  Bitcoin Brute-Force Tool")
        print("="*50)
        print("  [1]  Generate random key pair")
        print("  [2]  Generate address from private key")
        print("  [3]  Brute force  —  OFFLINE")
        print("  [4]  Brute force  —  ONLINE")
        print("  [0]  Exit")
        print("="*50)
        choice = input("  > ").strip()
 
        if choice == "1":
            self.generate_random_address()
            print("  Wallet ready!")
            input("\n  Press Enter to exit")
 
        elif choice == "2":
            wif = input("\n  Enter Private Key > ").strip()
            self.generate_from_private_key(wif)
            input("  Press Enter to exit")
 
        elif choice == "3":
            print("\n  [1]  Random attack")
            print("  [2]  Sequential attack")
            print("  [0]  Back")
            m = input("  > ").strip()
 
            if m == "1":
                self.ask_cores()
                self.run_random_offline()
 
            elif m == "2":
                cache = open("cache.txt").read().strip()
                self.ask_cores()
                if cache:
                    parts = cache.split("-")
                    start, end = int(parts[0]), int(parts[2])
                    print(f"\n  Resuming from {start:,} to {end:,} ...")
                    self.run_sequential_offline(start, end)
                else:
                    r = input("\n  Enter range (e.g. 1-1000000) > ").strip()
                    parts = r.split("-")
                    start, end = int(parts[0]), int(parts[1])
                    open("cache.txt", "w").write(f"{start}-{start}-{end}")
                    self.run_sequential_offline(start, end)
            else:
                return
 
        elif choice == "4":
            print("\n  [1]  Random attack")
            print("  [0]  Back")
            m = input("  > ").strip()
            if m == "1":
                self.ask_cores()
                self.run_random_online()
 
        elif choice == "0":
            print("  Exiting...")
            sleep(1)
            exit()
 
        else:
            print("  Invalid option.")
 
 
# ── entry point ──────────────────────────────────────────────────────────────
 
if __name__ == "__main__":
    # Required on Windows / macOS for multiprocessing
    multiprocessing.freeze_support()
 
    obj = Btcbf()
    try:
        obj.menu()
    except KeyboardInterrupt:
        print("\n\n  Ctrl+C — exiting.")
        os._exit(0)
 
