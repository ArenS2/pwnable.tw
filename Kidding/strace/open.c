main(){
	int fd = open(".", 0x200000, 0x400);
	char buf[100];
	getdents(fd, &buf, 100);
	write(1, &buf, 100);
}