#ifndef _MON_CPUINFO_H__
#define _MON_CPUINFO_H__

#include <stdio.h>
#include <string.h>
#include <libgen.h>
#include <sys/vfs.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdlib.h>
//#include "monM_def.h"

typedef struct _cpuinfo
{
    FILE *fp;                 // 파일 스트림 포인터
    char cpuname[50];         //1) cpu  : cpu 구분
    long long cpu_user;       //2) user : 사용자 영역 코드 실행 시간
    long long cpu_nice;       //3) system: 커널 영역 코드 실행 시간
    long long cpu_system;     //4) nice : 기본보다 낮은 우선순위로 실행한 사용자 영역 코드 실행 시간
    long long cpu_idle;       //5) idle : 대기 시간
    long long cpu_wait;       //6) wait : I/O 완료 대기 시간
    long long cpu_hi;         //7) hi : Hard Interrupt(IRQ)
    long long cpu_si;         //8) si : Soft Interrupt(SoftIRQ)
    long long cpu_zero;       //9) zero : 끝
} CPU_P;

CPU_P *cpu_dfopen();
CPU_P *cpu_dfget(CPU_P *CP);
void cpu_dfclose(CPU_P * CP);


#endif //mon_cpuinfo
