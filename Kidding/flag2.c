// file nay la source file trong thu muc flag dung de mo file flag neu input trung

#include <stdio.h>

int read_input(char *buf,unsigned int size){
    int ret ;
    ret = read(0,buf,size);
    if(ret <= 0){
        puts("read error");
        exit(1);
    }
    if(buf[ret-1] == '\n')
        buf[ret-1] = '\x00';
    return ret ;
}

int main(){
	char buf[100];
	setvbuf(stdin,0,2,0);
	setvbuf(stdout,0,2,0);
	printf("where is your flag :");
	read_input(buf,30);
	if(strcmp(buf,"./I_am_fl4g")){
		puts("No such flag !");
		return 1;
	}
	FILE *fp = fopen("./I_am_fl4g","r");
	if(!fp){
		puts("Open failed !");
	}
	fread(buf,1,30,fp);
	printf("Here is your flag: %s \n",buf);
	fclose(fp);
}
 \n",buf);
	fclose(fp);
}


// FLAG{Ar3_y0u_k1dd1ng_m3}