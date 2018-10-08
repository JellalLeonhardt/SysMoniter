#include "common.h"

static int get_char(int timeout)
{
	fd_set rfds;
	struct timeval tv;
	int ch = 0;
	FD_ZERO(&rfds);
	FD_SET(0, &rfds);
	tv.tv_sec = 0;
	tv.tv_usec = timeout; //设置等待超时时间
	if (select(1, &rfds, NULL, NULL, &tv) > 0)
	{
		ch = getchar(); 
	}
	return ch;
}

int main(){
	init();
	char chr;
	while(1){
		frame();
		sleep(1);
		chr = get_char(3000);
		if(chr == 'q'){
			break;
		}
	}
	getchar();
	return 0;
}
