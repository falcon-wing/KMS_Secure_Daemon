#include "mon_partitioninfo.h"

const char *PARTITIONS = "/proc/partitions";

PARTITION_P *part_dfopen()
{
	PARTITION_P *PRTP;

    	PRTP = (PARTITION_P *)malloc(sizeof(PARTITION_P));
    	if(!(PRTP->fp = fopen(PARTITIONS, "r")))
    	{
        	return NULL;
    	}
    	else
        	return PRTP;
}

void part_dfclose(PARTITION_P *PRTP)
{
	fclose (PRTP->fp);
}
