import hashlib
import itertools

def md5_brute_force(target_hash, length, charset="abcdefghijklmnopqrstuvwxyz_"):
    prefix = "PWNIL{"
    suffix = "}"
    for guess in itertools.product(charset, repeat=length):
        candidate = prefix + "".join(guess) + suffix
        hashed = hashlib.md5(candidate.encode()).hexdigest()
        print("try ", candidate, " -> ", hashed)
        if hashed == target_hash:
            return candidate
    return None

# Example usage
target_md5_hash = "537500469ddfc5b29e9379cdcc2f3c86"  # Replace with the MD5 hash you're targeting
max_length = 6  # Set the maximum length of <str>

found = None
for length in range(1, max_length + 1):
    found = md5_brute_force(target_md5_hash, length)
    if found:
        break

if found:
    print(f"Found match: {found}")
else:
    print("No match found.")
