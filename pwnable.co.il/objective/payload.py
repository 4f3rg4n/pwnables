from pwn import *

def new_obj(p: process, type: int = 3, data: str = "12345"):
    p.sendline("1")
    p.sendline(str(type))
    p.sendline(data)
    p.recvuntil("Exit")

def del_obj(p: process, index: int = 0):
    p.sendline("2")
    p.sendline(str(index))
    p.recvuntil("Exit") 

def edit_obj(p: process, index: int = 3, data: str = "12345"):
    p.sendline("3")
    p.sendline(str(index))
    p.sendline(data)
    p.recvuntil("Exit")
    
def main():
    ### run ###
    p = process("./objective")
    
    ### payload start ###

if __name__ == '__main__':
    main()