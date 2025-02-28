# solve.py

from pwn import *
import socket
import os

args = ['A']*100
args[ord('A')] = '\x00'
args[ord('B')] = '\x20\x0a\x0d'
env_var = {
    '\xde\xad\xbe\xef': '\xca\xfe\xba\xbe'
}
#print(int(args[ord('C')]))

p = process(executable='./input', argv=args, env=env_var)
p.sendline(b"\x00\x0a\x00\xff")

p.stderr.write(b"\x00\x0a\x02\xff")

import socket

HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 0  # Port to listen on (non-privileged ports are > 1023)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(b"\xde\xad\xbe\xef")

print(p.recvall(timeout=1).decode())
