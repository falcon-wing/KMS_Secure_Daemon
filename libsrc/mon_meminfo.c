#include "mon_meminfo.h"
#include "monM_def.h"

const char *MEMINFO  = "/proc/meminfo";

MEM_P *mem_dfopen()
{
    MEM_P *MP;
    // /proc/meminfo 파일을 연다.
    MP = (MEM_P *)malloc(sizeof(MEM_P));
    if(!(MP->fp = fopen(MEMINFO, "r") ))
    {
        return NULL;
    }
    else
        return MP;
}

MEM_P *mem_dfget(MEM_P *MP)
{
    char m_buf[1024];

    // /proc/meminfo 으로 부터 MEM 정보를 얻어온다.
    while(fgets(m_buf, 1024, MP->fp))
    {
        // MEM 항목중 필요한 항목만 추출한다.
        sscanf(m_buf, "%s",MP->memname);
        if (!strcmp(MP->memname,"MemTotal:")|| !strcmp( MP->memname,"MemFree:")|| !strcmp( MP->memname ,"Buffers:")|| !strcmp( MP->memname , "Cached:" )||
                 !strcmp( MP->memname , "SwapCached:" )|| !strcmp( MP->memname ,"SwapTotal:" )|| !strcmp( MP->memname ,"SwapFree:" ))

        {
            // MEM 시스템의 현재 사용량을 구한다.
            sscanf(m_buf, "%s %llu" ,MP->memname, &MP->mem_info);
            return MP;
        }
    }
    rewind(MP->fp);
    return NULL;
}

void mem_dfclose(MEM_P *MP)
{
	fclose(MP->fp);
}
