import hashlib
import itertools
import string

# Target MD5 hash
target_hash = "f87cd601aa7fedca99018a8be88eda34"

# Character set (adjust based on expected plaintext)
charset = string.ascii_letters + string.digits  # a-z, A-Z, 0-9

# Brute-force length range (adjust as needed)
min_length = 1
max_length = 5  # Increase if necessary

def md5_bruteforce():
    for length in range(min_length, max_length + 1):
        for attempt in itertools.product(charset, repeat=length):
            candidate = ''.join(attempt)
            candidate_hash = hashlib.md5(candidate.encode()).hexdigest()
            if candidate_hash == target_hash:
                print(f"[+] Found match: {candidate}")
                return candidate
    print("[-] No match found.")
    return None

if __name__ == "__main__":
    md5_bruteforce()
