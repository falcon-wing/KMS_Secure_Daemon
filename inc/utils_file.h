#ifndef _UTILS_FILE_H_
#define _UTILS_FILE_H_

#include <sys/errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <arpa/inet.h>
#include <netdb.h>

int set_fl(int fd, int flags);
int rot_file_getsize(int fd);
int rot_file_open(const char *path);
int rot_file_open_ex(const char *path, int mode);
int rot_file_open_ex_second(const char *path, int oflag, mode_t mode);
int rot_file_close(int fd);
int rot_file_create(const char *path);
int rot_file_create_ex(const char *path, mode_t mode);
int rot_file_copy(const char *src, const char *dest);
int rot_file_lock(int fd);
void rot_file_unlock(int fd);
int rot_file_getfilelock(char *szLockFile, mode_t _modeCreate, mode_t _modeOpen);
int lock_reg(int fd, int cmd, int type, off_t offset, int whence, off_t len);

int rot_file_isfile(char *path);
int rot_file_isdir(char *path);

int rot_file_createdir(const char *path);
FILE *rot_file_fopen(const char *filename, const char *mode);

#endif
