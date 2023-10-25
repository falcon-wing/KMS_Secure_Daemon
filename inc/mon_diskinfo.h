//mon_diskinfo
#ifndef _MON_DISKINFO_H__
#define _MON_DISKINFO_H__

#include <stdio.h>
#include <string.h>
#include <libgen.h>
#include <sys/vfs.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdlib.h>

#include "monM_def.h"

extern const char *DISKSTAT;

DISKSTAT_P *disk_dfopen();
DISKSTAT_P *disk_dfget(DISKSTAT_P *DSKP);
void disk_dfclose(DISKSTAT_P* DSKP);




#endif //_MON_DISKINFO_H__
