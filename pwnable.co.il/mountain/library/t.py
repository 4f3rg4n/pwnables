def register(p: process, username: str = "user", password: str = "12345"):
    p.sendline("1")
    p.sendline(username)
    p.sendline(password)

def login(p: process, username: str = "user", password: str = "12345"):
    p.sendline("2")
    p.sendline(username)
    p.sendline(password)

def borrow_book(p: process, book_idx: int = 0):
    p.sendline("1")
    p.sendline(str(book_idx))

def del_comment(p: process, id: int, book_idx: int = 0):
    p.sendline("3")
    p.sendline(str(book_idx))
    p.sendline(str(id))
    print("deleted: ", id)

def return_book(p: process, add_comment: bool = False, comment_len: int = 50, comment: str = "comment", title: str = "title", need_id: bool = True) -> int:
    id = 0
    p.sendline("2")
    if add_comment:
        p.sendline('Y')
        p.sendline(str(comment_len))
        p.sendline(title)
        p.sendline(comment)

        if need_id:
            p.recvuntil("Comment ")
            data = p.recvline().decode().split(' ')[0]
            id = int(data)
            print("id: ", id)
        else:
            print("no id")
    else:
        p.sendline('n')

    return id

def logout(p: process):
    p.sendline("Your choice: ", "4")












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
