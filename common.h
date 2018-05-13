#ifndef _COMMON_H
#define _COMMON_H

#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <termios.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <term.h>
#include <curses.h>
#include <fcntl.h>
#include <pwd.h>

void frame(void);
void init(void);

#endif
