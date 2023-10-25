#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <error.h>
#include <fcntl.h>
#include <unistd.h>
#include "monM_def.h"
#include "rot_utils.h"

extern char g_szLogFilename[MAX_FULLPATH_SIZE + 1];
extern char g_szLockFilename[MAX_FULLPATH_SIZE + 1];

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

int get_filelock(void)
{
        int ret;
        int fd = -1;
        int nCount = 0;

lock_reopen :
        if ( (fd = open(g_szLockFilename, O_CREAT|O_WRONLY, LOCK_FILEMODE)) == -1 )
        {
                if ( errno == EAGAIN || errno == EACCES )       /* AIX=EACCESS, SOLARIS=EAGAIN, HPUX=both */ /* log file is locked */
                {
                        nCount++;
                        if (nCount == 3)
                                return -1;

                        goto lock_reopen;
                }
                else
                        return -1;
        }

relock :
        lseek(fd, 0, SEEK_SET);
        if ( lockf(fd, F_TLOCK, 1) == -1 )  /*lock test */
        {
                if ( errno == EAGAIN || errno == EACCES )       /* AIX=EACCESS, SOLARIS=EAGAIN, HPUX=both */
                {
                        nCount++;
                        if (nCount == 3)
                                return -1;

                        goto relock;
                }
                else
                {
                        close(fd);
                        return -1;
                }
        }

        return fd;
}

void free_filelock(int fd)
{
        int ret;

refree:
        ret = close(fd);
        if (ret == -1)
        {
                if (errno == EINTR)
                        goto refree;
        }
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




















