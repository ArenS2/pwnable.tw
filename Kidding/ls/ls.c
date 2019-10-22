main(){
	char *temp[] = {"/bin/locate", "flag" ,0};
	execve("/bin/locate", temp, 0);
}