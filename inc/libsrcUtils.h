#ifndef _LIBSRCUTILS_H_
#define _LIBSRCUTILS_H_

#include "utils_file.h"
#include "utils_str.h"
#include "rot_rule_oper.h"
#include "rot_utils.h"

#define MU_FILEMODE (S_IRUSR | S_IRGRP | S_IROTH)
#define MU_RLOCKMODE ((MU_FILEMODE & ~S_IXGRP) | S_ISGID)

#define read_lock(fd, offset, whence, len) \
    lock_reg(fd, F_SETLK, F_RDLCK, offset, whence, len)
#define write_lock(fd, offset, whence, len) \
    lock_reg(fd, F_SETLK, F_WRLCK, offset, whence, len)
#define un_lock(fd, offset, whence, len) \
    lock_reg(fd, F_SETLK, F_UNLCK, offset, whence, len)

int do_rotlog(char *fn, int level, int logtype, const char *fmt, ...);
#endif