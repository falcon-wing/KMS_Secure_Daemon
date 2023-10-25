#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct ProcInfo {
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
} ;

char *xstrchr(char *string, int delimiter);
char *xstrtok(char *string, int delimiter, int slot);
