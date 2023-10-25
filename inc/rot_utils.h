#ifndef _ROT_UTILS_H__
#define _ROT_UTILS_H__
#include <stdio.h>
#include <stdlib.h>
//#include <procinfo.h>
#include "utils_str.h"
#include "utils_file.h"

#ifndef	PATH_MAX
  #define PATH_MAX	4096
#endif

#define STR_MAX		256
#define UTIL_MAX	16384

#define TICKS		sysconf(_SC_CLK_TCK)
#define PAGESIZE	sysconf(_SC_PAGESIZE)
/*
struct procinfo {
	pid_t pid;
	pid_t ppid;
	char dir[PATH_MAX];
	char cmd[STR_MAX];
	char parent_cmd[STR_MAX];
	char exe[PATH_MAX];
	char cwd[PATH_MAX];
	char state;
	unsigned int fds;
	unsigned int threads_count;
	size_t *threads;
	uid_t uid;
	gid_t gid;
	char user[STR_MAX];
	char group[STR_MAX];
	size_t vsz;
	size_t rss;
	size_t shr;
	unsigned long long cpu_sec;
	time_t pid_ctime;
};
*/

typedef struct ProcInfo__ {
        char
                user[10],       /* user name corresponding to owner of process */
                cmd[40],        /* basename of executable file in call to exec(2) */
                state,          /* single-char code for process state (S=sleeping) */
                ttyc[5],        /* string representation of controlling tty device */
                **environ,      /* environment string vector (/proc/#/environ) */
                **cmdline;      /* command line string vector (/proc/#/cmdline) */
        int
                uid,            /* user id */
                pid,            /* process id */
                ppid,           /* pid of parent process */
                pgrp,           /* process group id */
                session,        /* session id */
                tty,            /* full device number of controlling terminal */
                tpgid,          /* terminal process group id */
                priority,       /* kernel scheduling priority */
                nice;           /* standard unix nice level of process */
        long long
                signal,         /* mask of pending signals */
                blocked,        /* mask of blocked signals */
                sigignore,      /* mask of ignored signals */
                sigcatch;       /* mask of caught  signals */
        long
                start_time,     /* start time of process -- seconds since 1-1-70 */
                utime,          /* user-mode CPU time accumulated by process */
                stime,          /* kernel-mode CPU time accumulated by process */
                cutime,         /* cumulative utime of process and reaped children */
                cstime,         /* cumulative stime of process and reaped children */
                                        /* the next 7 members come from /proc/#/statm */
                size,           /* total # of pages of memory */
                resident,       /* number of resident set (non-swapped) pages (4k) */
                share,          /* number of pages of shared (mmap'd) memory */
                trs,            /* text resident set size */
                lrs,            /* shared-lib resident set size */
                drs,            /* data resident set size */
                dt;                     /* dirty pages */
        unsigned
                pcpu;           /* %CPU usage (is not filled in by readproc!!!) */
        unsigned long
                vsize,          /* number of pages of virtual memory ... */
                rss,            /* resident set size from /proc/#/stat */
                rss_rlim,       /* resident set size ... ? */
                timeout,        /* ? */
                it_real_value,  /* ? */
                flags,          /* kernel flags for the process */
                min_flt,        /* number of minor page faults since process start */
                maj_flt,        /* number of major page faults since process start */
		cmin_flt,       /* cumulative min_flt of process and child processes */
                cmaj_flt,       /* cumulative maj_flt of process and child processes */
                start_code,     /* address of beginning of code segment */
                end_code,       /* address of end of code segment */
                start_stack,    /* address of the bottom of stack for the process */
                kstk_esp,       /* kernel stack pointer */
                kstk_eip,       /* kernel stack pointer */
                wchan;          /* address of kernel wait channel proc is sleeping in */
        struct proc_s *l,       /* ptrs for building arbitrary linked structs */
                      *r;       /* (i.e. singly/doubly-linked lists and trees */
} ProcInfo___t;

#define read_lock(fd, offset, whence, len) \
    lock_reg(fd, F_SETLK, F_RDLCK, offset, whence, len)
#define write_lock(fd, offset, whence, len) \
    lock_reg(fd, F_SETLK, F_WRLCK, offset, whence, len)
#define un_lock(fd, offset, whence, len) \
    lock_reg(fd, F_SETLK, F_UNLCK, offset, whence, len)

char *rot_getcwd();
unsigned int get_bytetoMbyte(int iMbyte);
time_t get_ctime(void);
int time_to_str(time_t tTime, char *szDateTime);

int rot_unlink(const char *path);

pid_t get_pid(char *szPidPath);
int do_cmd_set(char *szCmd);
int do_cmd_setV2(char * szCmd, char *szCmdFullPath);
int is_num(char *arg);
int is_file(char *path);
int find_process(pid_t nPid, char *szName);
bool NeedUpdateDate(/*char * szData*/ );
#endif
