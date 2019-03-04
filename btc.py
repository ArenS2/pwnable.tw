from hashlib import sha256
from random import random 

ser = "2490153c6290f5c878b566e6e75b53c8b3fac970d1456309225aac1bcb627972"
bao = "a9d9e39b4b5ccdbbf7b919a629fcaa31c5c4fb3e8265f11582d03caaf4095ef1"
l3t = "a76ad9d9cf8c06d26e7cf06de7b13ee16a1ca144e649203fb19845fbe281f871"
nkb = "4912c298ff29d49f5823a6145b130c9fac23464d2ee17211980765b2e2d9737b"

while(1):
	rand_number = str(random())[2:] + str(random())[2:]
	for i in range(1000000):
		guess = sha256(rand_number).hexdigest()
		if(guess == ser or guess == bao or guess == l3t or guess == nkb):
			f = open("result.txt", "a")
			f.write(rand_number)
			f.close()
		rand_number = guess
		
