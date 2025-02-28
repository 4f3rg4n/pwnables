import hashlib
import itertools
import string

# Function to compute the MD5 hash of a string
def get_md5_hash(s):
    return hashlib.md5(s.encode('utf-8')).hexdigest()

# Function to brute-force the flag
def brute_force_flag():
    # Define the possible characters that might appear in the flag (lowercase letters and numbers)
    characters = string.ascii_lowercase + string.digits

    # We will brute-force the flag length from 1 to 10 characters (you can adjust this range based on the flag's length)
    for length in range(1, 11):  # Adjust length if needed
        for guess in itertools.product(characters, repeat=length):
            guess_str = ''.join(guess) + "\n"
            hash_guess = get_md5_hash(guess_str)
            
            # Print the guess and its corresponding hash
            print(f"Trying: {guess_str} --> MD5: {hash_guess}")
            
            if hash_guess.startswith("537500"):
                print(f"Found matching str: {guess_str}")
                return guess_str

    print("Flag not found within specified length range.")
    return None

if __name__ == "__main__":
    brute_force_flag()
