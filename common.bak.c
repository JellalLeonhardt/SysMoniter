#include "common.h"

char str[100] = " ";

void init(void){
	setupterm(NULL, STDOUT_FILENO, NULL);
	putp(clear_screen);
	putp("This is for test\ncol1\ncol2\n");
	getchar();
}

void sysInfo(void){

}

//void taskInfo(void){
//
//}

void frame(void){
	putp(tgoto(cursor_address, 0, 3));
	//putp(clear_screen);
	putp(clr_eol);
	strcat(str,"AS");
	str[0] += 1;
	putp(str);
	putp(clr_eos);
}
