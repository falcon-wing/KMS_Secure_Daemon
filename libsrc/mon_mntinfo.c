#include "mon_mntinfo.h"

const char *MMOUNT     = "/proc/mounts";
//extern const char *MMOUNT;

MOUNT_P *mnt_dfopen()
{
    MOUNT_P *MNTP;

    // /proc/mounts 파일을 연다.
    MNTP = (MOUNT_P *)malloc(sizeof(MOUNT_P));
    if(!(MNTP->fp = fopen(MMOUNT, "r")))
    {
        return NULL;
    }
    else
        return MNTP;
}

MOUNT_P *mnt_dfget(MOUNT_P *MNTP)
{
    char d_buf[256];
    struct statfs lstatfs;
    struct stat lstat;
    int is_root = 0;

    // /proc/mounts로 부터 마운트된 파티션의 정보를 얻어온다.
    while(fgets(d_buf, 255, MNTP->fp))
    {
        is_root = 0;
        sscanf(d_buf, "%s%s%s",MNTP->devname, MNTP->mountdir, MNTP->fstype);
        if (strcmp(MNTP->mountdir,"/") == 0) is_root=1;
        if (stat(MNTP->devname, &lstat) == 0 || is_root)
        {
            if (strstr(d_buf, MNTP->mountdir) && S_ISBLK(lstat.st_mode) || is_root)
            {
                // 파일시스템의 총 할당된 크기와 사용량을 구한다.
                statfs(MNTP->mountdir, &lstatfs);
                MNTP->size.blocks = lstatfs.f_blocks * (lstatfs.f_bsize / 1024 ) / 1024 ;
                MNTP->size.avail  = lstatfs.f_bavail * (lstatfs.f_bsize / 1024 ) / 1024 ;
                MNTP->size.used   = MNTP->size.blocks - MNTP->size.avail ;
                return MNTP;
            }
        }
    }
    rewind(MNTP->fp);
    return NULL;
}

void mnt_dfclose(MOUNT_P * MNTP)
{
	fclose (MNTP->fp);
}
