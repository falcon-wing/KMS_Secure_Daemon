#include "mon_diskinfo.h"

const char *DISKSTAT   = "/proc/diskstats";

DISKSTAT_P *disk_dfopen()
{
    DISKSTAT_P *DSKP;

    // /proc/diskstats 파일을 연다.
    DSKP = (DISKSTAT_P *)malloc(sizeof(DISKSTAT_P));
    if(!(DSKP->fp = fopen(DISKSTAT, "r")))
    {
        return NULL;
    }
    else
        return DSKP;
}

DISKSTAT_P *disk_dfget(DISKSTAT_P *DSKP)
{
    char buf[1024];

    // /proc/partitions 로 부터 마운트된 파티션의 정보를 얻어온다.
    while(fgets(buf, 1023, DSKP->fp))
    {
         // 파일시스템의 총 할당된 크기와 사용량을 구한다.
         sscanf(buf, "%s%s%s%lu%lu%lu%lu%lu%lu%lu%lu%lu%lu"
              ,DSKP->temp1, DSKP->temp1, DSKP->diskname, &DSKP->red_compl, &DSKP->red_merge, &DSKP->red_sectr, &DSKP->red_milsc, &DSKP->wrt_comp, &DSKP->wrt_sect, &DSKP->wrt_mils, &DSKP->io_c_prc, &DSKP->io_comp, &DSKP->io_mils);
         return DSKP;

    }
    rewind(DSKP->fp);
    return NULL;
}

void disk_dfclose(DISKSTAT_P *DSKP)
{
	fclose (DSKP->fp);
}
