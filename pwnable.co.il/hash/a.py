import hashlib
import itertools
import string

# MD5 hash of the flag that the server provides
target_hash = '537500469ddfc5b29e9379cdcc2f3c86'

# The known prefix of the flag format
flag_prefix = "PWNIL{"

# Function to compute the MD5 hash of a string
def get_md5_hash(s):
    return hashlib.md5(s.encode('utf-8')).hexdigest()

# Function to brute-force the flag
def brute_force_flag():
    # Define the possible characters that might appear in the flag (only lowercase letters)
    characters = string.ascii_lowercase

    # We will brute-force the flag length from 1 to 10 characters (you can adjust this range based on the flag's length)
    for length in range(1, 11):  # Adjust length if needed
        for guess in itertools.product(characters, repeat=length):
            guess_str = flag_prefix + ''.join(guess) + '}'
            hash_guess = get_md5_hash(guess_str)
            
            # Print the guess and its corresponding hash
            print(f"Trying: {guess_str} --> MD5: {hash_guess}")
            
            if hash_guess == target_hash:
                print(f"Found matching flag: {guess_str}")
                return guess_str

    print("Flag not found within specified length range.")
    return None

if __name__ == "__main__":
    brute_force_flag()
