#ifndef _MON_MEMINFO_H__
#define _MON_MEMINFO
#include <stdio.h>
#include <string.h>
#include <libgen.h>
#include <sys/vfs.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdlib.h>
#include "monM_def.h"

//extern const char *MEMINFO;



MEM_P *mem_dfopen();
MEM_P *mem_dfget(MEM_P *MP);
void mem_dfclose(MEM_P * MP);



#endif
