#include "common.h"

int main(){
	init();
	int cnt = 10000;
	while(cnt--){
		frame();
	}
	getchar();
	return 0;
}
