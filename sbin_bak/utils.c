#include <stdlib.h>
#include <strings.h>
#include <time.h>
#include <string.h>

#include <sys/procfs.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/procfs.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include "utils.h"
#include "def.h"

#define STR_MAX         256
#define UTIL_MAX        16384

#define TICKS           sysconf(_SC_CLK_TCK)
#define PAGESIZE        sysconf(_SC_PAGESIZE)

int set_errno(int err)
{
        errno = err;
        return -1;
}

int s_isreg(unsigned short _st_mode)
{
       if (S_ISREG(_st_mode))
                return TRUE;
        else
                return FALSE;
}

char *rot_getcwd()
{
        char *strCurPath = malloc(MAX_FULLPATH_SIZE);
        getcwd(strCurPath, MAX_FULLPATH_SIZE);

        return strCurPath;
}

unsigned int get_bytetoMbyte(int iMbyte)
{
        return (iMbyte * 1000000);
}

time_t get_ctime(void)
{
        struct timeval tv;
        struct timezone tz;
        int ret;

        ret = gettimeofday(&tv, &tz);
        if (ret == -1)
        {
                //_DEBUGLOG("GET_TIME", LV_DEBUG, "Gettimeofday : %s", get_strErrMsg(errno));
                return -1L;
        }

        return tv.tv_sec;
}

int rot_unlink(const char *path)
{
        int ret;

        if ((ret = unlink(path)) == -1)
        {
                if (errno == EACCES) // SO ±ÇÇÑÀ¸·Î º¯°æ
                {
                        //     SetSOProc("_set_");

                        ret = unlink(path);
                }
        }

        return ret;
}

int time_to_str(time_t tTime, char *szDateTime)
{
        struct tm *ptmTime;

        ptmTime = localtime(&tTime);

        sprintf(szDateTime, "%04d%02d%02d%02d%02d%02d",
                ptmTime->tm_year + 1900, ptmTime->tm_mon + 1, ptmTime->tm_mday,
                ptmTime->tm_hour, ptmTime->tm_min, ptmTime->tm_sec);

        return 0;
}
/*
char *strip_whitechar(char *buf)
{
        int flag=1;
        char *tp;

        tp = NULL;

        if (buf == NULL)
                return NULL;

        while(*buf)
        {
                if (isspace((int)*buf))
                {
                        // counting white space 
                        if (flag == 2)
                        {
                                *buf = 0x00;
                                flag = 0;
                                break;
                        }
                }
                else
                {
                        // counting alpha-numeric character 
                        if (flag == 1)
                        {
                                tp = buf;
                                flag = 2;
                        }
                }

                *buf++;
        }

        if (flag != 1)
                return tp;

        return NULL;
}
*/
////////////////////////////
//<FILE>

int set_fl(int fd, int flags)
{
    int val;

    if ((val = fcntl(fd, F_GETFL, 0)) < 0)
        return -1;

    val |= flags;

    if (fcntl(fd, F_SETFL, val) < 0)
        return -1;

    return 0;
}

int rot_file_getsize(int fd)
{
    struct stat buf;

    if (fstat(fd, &buf) == 0)
    {
        return buf.st_size;
    }
    else
    {
        return -1;
    }
}

int rot_file_open(const char *path)
{
    return rot_file_open_ex(path, CREATE_MODE);
}

int rot_file_open_ex(const char *path, int mode)
{
    int fd;
    struct stat statbuf;
    int locktype;

    if (path == NULL)
    {
        return -1;
    }

    if (access(path, F_OK) < 0)
    {
        if (mode == O_RDONLY)
        {
            return -1;
        }

        //))
    }

    return 0;
}

int rot_file_open_ex_second(const char *path, int oflag, mode_t mode)
{
    int ret;

    if ((ret = open(path, oflag, mode)) == -1)
    {
        if (errno == EACCES) // SO ±ÇÇÑÀ¸·Î º¯°æ
        {
            ret = open(path, oflag, mode);
        }
    }

    return ret;
}

int rot_file_close(int fd)
{
    int ret = 0;

    return ret;
}

int rot_file_createdir(const char *path)
{
    int ret = 0;
    struct stat st = {0};

    ret = stat(path, &st);
    if (ret == -1)
    {

        ret = mkdir(path, 755);
    }

    return ret;
}

int rot_file_create(const char *path)
{
    int ret = 0;

    return rot_file_create_ex(path, CREATE_MODE);
}

int rot_file_create_ex(const char *path, mode_t mode)
{
    int fd;

    if ((fd = open(path, O_RDWR | O_CREAT | O_TRUNC, mode)) < 0)
    {
        return -1;
    }

    set_fl(fd, O_NONBLOCK);

    return fd;
}

int rot_file_copy(const char *src, const char *dest)
{
    int fd_s, fd_t;
    int isize;
    char *buff = NULL;

    if ((fd_s = rot_file_open_ex(src, O_RDONLY)) < 0)
    {
        return -1;
    }

    if ((fd_t = rot_file_open_ex(dest, O_RDONLY)) < 0)
    {
        rot_file_close(fd_s);
        return -1;
    }

    if ((isize = rot_file_getsize(fd_s)) < 0)
    {
        rot_file_close(fd_s);
        rot_file_close(fd_t);
        return -1;
    }

    if (isize > 0)
    {

        if ((buff = (char *)malloc(isize)) == NULL)
        {
            rot_file_close(fd_s);
            rot_file_close(fd_t);
            return -1;
        }

        if (read(fd_s, buff, isize) != isize)
        {
            rot_file_close(fd_s);
            rot_file_close(fd_t);

            free(buff);
            return -1;
        }

        ftruncate(fd_t, 0);
    }
}

int rot_file_lock(int fd)
{
    if (fchmod(fd, MU_RLOCKMODE) < 0)
    {
        return -1;
    }

    if (write_lock(fd, 0, SEEK_SET, 0) < 0)
    {
        return -1;
    }

    return 0;
}

void rot_file_unlock(int fd)
{
    un_lock(fd, 0, SEEK_SET, 0);
}

int rot_file_getfilelock(char *szLockFile, mode_t _modeCreate, mode_t _modeOpen)
{
    int fd = 0;

lock_reopen:
    if ((fd = rot_file_open_ex_second(szLockFile, O_CREAT | O_WRONLY, _modeOpen)) == -1)
    {
        if (errno == EAGAIN)
            goto lock_reopen;
        else
            return -1;
    }
relock:
    lseek(fd, 0, SEEK_SET);
    if (lockf(fd, F_TLOCK, 1) == -1) /* lock test */
    {
        if ((errno == EAGAIN) || (errno == EACCES))
            goto relock;
        else
        {
            close(fd);
            return -1;
        }
    }
}

int lock_reg(int fd, int cmd, int type, off_t offset, int whence, off_t len)
{
    struct flock lock;

    lock.l_type = type;
    lock.l_start = offset;
    lock.l_whence = whence;
    lock.l_len = len;

    return (fcntl(fd, cmd, &lock));
}

int rot_file_isfile(char *path)
{
    int ret;
    struct stat st;

    ret = stat(path, &st);
    if (ret < 0)
        return -1;

    if (S_ISREG(st.st_mode))
        return TRUE;
    else
        return FALSE;
}

int rot_file_isdir(char *path)
{
    int ret;
    struct stat st;

    ret = stat(path, &st);
    if (ret < 0)
        return E_RET;

    if (S_ISDIR(st.st_mode))
        return TRUE;
    else
        return FALSE;
}

FILE *rot_file_fopen(const char *filename, const char *mode)
{
    FILE *fp;

    if ((fp = fopen(filename, mode)) == NULL)
    {
        if (errno == EACCES)
        {
            fp = fopen(filename, mode);
        }
    }
    return fp;
}












