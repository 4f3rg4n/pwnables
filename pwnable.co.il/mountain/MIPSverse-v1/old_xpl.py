from pwn import *

def GenExit():
    return b"\x0C\x00\x00\x00"

def main():
    ### run ###
    p = process("./MIPSverse")
    #p = remote("pwnable.co.il", 9020)

    ### payload start ###
    payload = b""
    payload += GenExit()

    p.sendline(str(len(payload) // 4))
    p.sendline(payload)

    print(p.recvall(timeout=0.1).decode())
    #p.interactive()

if __name__ == "__main__":
    main()