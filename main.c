#include "common.h"

int main(){
	init();
	int cnt = 10000;
	while(cnt--){
		frame();
		sleep(1);
	}
	getchar();
	return 0;
}
