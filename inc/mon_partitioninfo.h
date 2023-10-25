#ifndef _MON_PARTITIONINFO_H__
#define _MON_PARTITIONINFO_H__

#include <stdio.h>
#include <string.h>
#include <libgen.h>
#include <sys/vfs.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdlib.h>
#include "monM_def.h"

extern const char *PARTITIONS;

PARTITION_P *part_dfopen();
void part_dfclose(PARTITION_P *PRTP);


#endif //_MON_PARTITIONINFO_H__
