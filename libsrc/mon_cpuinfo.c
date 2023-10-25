
#include <stdio.h>
#include <string.h>
#include <libgen.h>
#include <sys/vfs.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdlib.h>
#include "mon_cpuinfo.h"
#include "monM_def.h"

//extern const char *CPUSTAT;
const char *CPUSTAT    = "/proc/stat";

/*
 *
 */
CPU_P *cpu_dfopen()
{
//    const char *CPUSTAT    = "/proc/stat";
    CPU_P *CP;
    // /proc/stat 파일을 연다.
    CP = (CPU_P *)malloc(sizeof(CPU_P));
    if(!(CP->fp = fopen(CPUSTAT, "r")) )
    {
        return NULL;
    }
    else
        return CP;
}

CPU_P *cpu_dfget(CPU_P *CP)
{
    char c_buf[1024];

    // /proc/stat 으로 부터 CPU 정보를 얻어온다.
    while(fgets(c_buf, 1024, CP->fp))
    {
        sscanf(c_buf, "%s",CP->cpuname);
        if (strncmp(CP->cpuname,"cpu",3) == 0)
        {
            // CPU 시스템의 현재 사용량을 구한다.
            sscanf(c_buf, "%s %llu %llu %llu %llu %llu %llu %llu %llu"
                ,CP->cpuname, &CP->cpu_user, &CP->cpu_nice, &CP->cpu_system, &CP->cpu_idle, &CP->cpu_wait, &CP->cpu_hi, &CP->cpu_si, &CP->cpu_zero);
            return CP;
        }
    }
    rewind(CP->fp);
    return NULL;
}

void cpu_dfclose(CPU_P * CP)
{
	fclose(CP->fp);
}
