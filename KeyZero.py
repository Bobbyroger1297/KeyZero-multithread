import requests
from bit import Key
from time import sleep, time
import os
import multiprocessing
from multiprocessing import Pool, cpu_count, Value

# ── module-level globals (populated via pool initializer) ────────────────────
# These are set in each worker process via _pool_init() so they never need
# to be pickled and sent over the pipe — fixing the Windows spawn error.

_g_addresses  = None   # frozenset of target addresses
_g_counter    = None   # shared Value('Q') — keys checked
_g_found_flag = None   # shared Value('b') — 1 when match found


def _pool_init(addresses, counter, found_flag):
    """Called once per worker process at startup (safe on Windows spawn)."""
    global _g_addresses, _g_counter, _g_found_flag
    _g_addresses  = addresses
    _g_counter    = counter
    _g_found_flag = found_flag


# ── worker functions (module-level for pickling) ─────────────────────────────

def _random_brute_worker(n):
    if _g_found_flag.value:
        return
    key = Key()
    with _g_counter.get_lock():
        _g_counter.value += 1
    if key.address in _g_addresses:
        _g_found_flag.value = 1
        _save_found(key.address, key.to_wif())
        os._exit(0)


def _sequential_brute_worker(n):
    if _g_found_flag.value:
        return
    key = Key.from_int(n)
    with _g_counter.get_lock():
        _g_counter.value += 1
    if key.address in _g_addresses:
        _g_found_flag.value = 1
        _save_found(key.address, key.to_wif())
        os._exit(0)


def _online_brute_worker(n):
    if _g_found_flag.value:
        return
    key = Key()
    with _g_counter.get_lock():
        _g_counter.value += 1
    try:
        resp = requests.get(
            f"https://blockchain.info/q/getreceivedbyaddress/{key.address}/",
            timeout=10
        ).text
        if int(resp) > 0:
            _g_found_flag.value = 1
            _save_found(key.address, key.to_wif())
            os._exit(0)
    except Exception:
        pass


def _save_found(address, wif):
    print(f"\n{'='*52}")
    print(f"  *** MATCHING ADDRESS FOUND ***")
    print(f"  Public Address : {address}")
    print(f"  Private Key    : {wif}")
    print(f"{'='*52}\n")
    with open("foundkey.txt", "a") as f:
        f.write(address + "\n")
        f.write(wif + "\n")


# ── speed monitor (its own daemon process) ───────────────────────────────────

def _speed_monitor(counter, start_t, label):
    prev = 0
    while True:
        sleep(2)
        n = counter.value
        elapsed = time() - start_t
        rate = abs(n - prev) // 2
        h, rem = divmod(int(elapsed), 3600)
        m, s   = divmod(rem, 60)
        print(
            f"  [{label}]  checked: {n:,}  |  {rate:,}/s  |  {h:02}:{m:02}:{s:02}   ",
            end="\r"
        )
        prev = n


# ── main class ───────────────────────────────────────────────────────────────

class Btcbf:
    def __init__(self):
        self.cores = cpu_count()

        # Shared memory — created in the main process, inherited by workers
        self.counter    = Value('Q', 0)   # keys checked (unsigned 64-bit)
        self.found_flag = Value('b', 0)   # match found flag

        if not os.path.exists("address.txt"):
            print("  WARNING: address.txt not found.")
            self.loaded_addresses = frozenset()
        else:
            lines = [l.strip() for l in open("address.txt") if 'wallet' not in l and l.strip()]
            self.loaded_addresses = frozenset(lines)
            print(f"  Loaded {len(self.loaded_addresses):,} target addresses.")

        if not os.path.exists("cache.txt"):
            open("cache.txt", "w").close()

    # ── helpers ──────────────────────────────────────────────────────────────

    def ask_cores(self):
        available = cpu_count()
        ans = input(f"\n  Available cores: {available}  —  How many to use? (Enter = all) > ").strip()
        if ans == "":
            self.cores = available
        elif ans.isdigit():
            c = int(ans)
            if 0 < c <= available:
                self.cores = c
            elif c > available:
                yn = input(f"  Only {available} available. Use {c} anyway? [y/n] > ")
                self.cores = c if yn.lower() == "y" else available
            else:
                print("  Invalid."); exit()
        else:
            print("  Invalid input."); exit()
        print(f"  Using {self.cores} core(s).\n")

    def _make_pool(self):
        """
        Workers inherit shared Values via the initializer.
        Nothing is pickled through the pipe — safe on Windows spawn.
        """
        return Pool(
            processes=self.cores,
            initializer=_pool_init,
            initargs=(self.loaded_addresses, self.counter, self.found_flag)
        )

    def _start_monitor(self, label):
        p = multiprocessing.Process(
            target=_speed_monitor,
            args=(self.counter, time(), label),
            daemon=True
        )
        p.start()
        return p

    # ── attack runners ────────────────────────────────────────────────────────

    def run_random_offline(self):
        self._start_monitor("OFFLINE-RANDOM")
        print(f"  Running random offline attack on {self.cores} core(s) ...\n")

        def itr():
            i = 0
            while not self.found_flag.value:
                yield i
                i += 1

        with self._make_pool() as pool:
            for _ in pool.imap_unordered(_random_brute_worker, itr(), chunksize=500):
                if self.found_flag.value:
                    pool.terminate()
                    break

    def run_sequential_offline(self, start, end):
        self._start_monitor("OFFLINE-SEQ")
        print(f"  Running sequential offline attack [{start:,} -> {end:,}] on {self.cores} core(s) ...\n")

        with self._make_pool() as pool:
            for _ in pool.imap_unordered(_sequential_brute_worker, range(start, end), chunksize=1000):
                if self.found_flag.value:
                    pool.terminate()
                    break

        open("cache.txt", "w").close()
        print("\n  Range complete.")

    def run_random_online(self):
        self._start_monitor("ONLINE-RANDOM")
        print(f"  Running random online attack on {self.cores} core(s) ...\n")

        def itr():
            i = 0
            while not self.found_flag.value:
                yield i
                i += 1

        with self._make_pool() as pool:
            for _ in pool.imap_unordered(_online_brute_worker, itr(), chunksize=10):
                if self.found_flag.value:
                    pool.terminate()
                    break

    # ── key utilities ─────────────────────────────────────────────────────────

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

    # ── menu ──────────────────────────────────────────────────────────────────

    def menu(self):
        print("\n" + "="*52)
        print("  Bitcoin Brute-Force Tool")
        print("="*52)
        print("  [1]  Generate random key pair")
        print("  [2]  Generate address from private key")
        print("  [3]  Brute force  —  OFFLINE")
        print("  [4]  Brute force  —  ONLINE")
        print("  [0]  Exit")
        print("="*52)
        choice = input("  > ").strip()

        if choice == "1":
            self.generate_random_address()
            input("\n  Press Enter to exit")

        elif choice == "2":
            wif = input("\n  Enter Private Key > ").strip()
            self.generate_from_private_key(wif)
            input("  Press Enter to exit")

        elif choice == "3":
            print("\n  [1]  Random attack\n  [2]  Sequential attack\n  [0]  Back")
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
                    print(f"\n  Resuming {start:,} -> {end:,} ...")
                    self.run_sequential_offline(start, end)
                else:
                    r = input("\n  Enter range (e.g. 1-1000000) > ").strip().split("-")
                    start, end = int(r[0]), int(r[1])
                    open("cache.txt", "w").write(f"{start}-{start}-{end}")
                    self.run_sequential_offline(start, end)

        elif choice == "4":
            print("\n  [1]  Random attack\n  [0]  Back")
            m = input("  > ").strip()
            if m == "1":
                self.ask_cores()
                self.run_random_online()

        elif choice == "0":
            print("  Exiting..."); sleep(1); exit()
        else:
            print("  Invalid option.")


# ── entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    multiprocessing.freeze_support()   # required for Windows
    obj = Btcbf()
    try:
        obj.menu()
    except KeyboardInterrupt:
        print("\n\n  Ctrl+C — exiting.")
        os._exit(0)
_exit(0)
