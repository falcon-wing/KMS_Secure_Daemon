#ifndef _UTILS_H__
#define _UTILS_H__
#include <stdio.h>
#include <stdlib.h>

#define read_lock(fd, offset, whence, len) \
    lock_reg(fd, F_SETLK, F_RDLCK, offset, whence, len)
#define write_lock(fd, offset, whence, len) \
    lock_reg(fd, F_SETLK, F_WRLCK, offset, whence, len)
#define un_lock(fd, offset, whence, len) \
    lock_reg(fd, F_SETLK, F_UNLCK, offset, whence, len)

char *rot_getcwd();
unsigned int get_bytetoMbyte(int iMbyte);
time_t get_ctime(void);
int time_to_str(time_t tTime, char *szDateTime);

int rot_unlink(const char *path);

#endif
