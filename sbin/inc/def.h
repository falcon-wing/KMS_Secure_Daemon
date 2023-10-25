#ifndef _DEF_H__
#define _DEF_H__
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

//<log def>

#ifndef LV_DEBUG
#define LV_DEBUG 0
#endif

#ifndef LV_INFO
#define LV_INFO 2
#endif

#ifndef LV_ERR
#define LV_ERR 1
#endif

#ifndef PRODUCT
#define PRODUCT "monDamon"
#endif

#ifndef MAX_SLOG_LINE_SIZE
#define MAX_SLOG_LINE_SIZE 4096//2047
#endif

#ifndef ROTD_PRODUCT_NAME
#define ROTD_PRODUCT_NAME "ROTDAMON"
#endif

#ifndef LOCK_FILEMODE
#define LOCK_FILEMODE 02600
#endif

//
#define LOCKMODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

#ifndef CREATE_MODE
#define CREATE_MODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)
#endif

#ifndef CREATE_MODE2
#define CREATE_MODE2 (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)
#endif

#ifndef CT_FILEMODE
#define CT_FILEMODE (S_IRUSR | S_IRGRP | S_IROTH)
#endif

#ifndef CT_WRMODE
#define CT_WRMODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)
#endif

#ifndef CT_WLOCKMODE
#define CT_WLOCKMODE ((CT_WRMODE & ~S_IXGRP) | S_ISGID)
#endif

#ifndef MU_FILEMODE
#define MU_FILEMODE (S_IRUSR | S_IRGRP | S_IROTH)
#endif

#ifndef MU_RLOCKMODE
#define MU_RLOCKMODE ((MU_FILEMODE & ~S_IXGRP) | S_ISGID)
#endif

#ifndef ROOT_PATH
#define ROOT_PATH   "/usr/local/ictk"
#endif

#ifndef MONADMIN_DAEMON
#define MONADMIN_DAEMON		"monD"
#endif

#ifndef MAINDAEMON_PRODUCTNAME
#define MAINDAEMON_PRODUCTNAME 	"wd_worker"
#endif

#ifndef ETC_DIR
#define ETC_DIR  "etc"
#endif

#ifndef JSON_SUBOBJNAME_REQ
#define JSON_SUBOBJNAME_REQ     "request"
#endif

#ifndef JSON_SUBOBJNAME_TAR
#define JSON_SUBOBJNAME_TAR     "target"
#endif

#ifndef JSON_SUBOBJNAME_HEADER
#define JSON_SUBOBJNAME_HEADER  "header"
#endif

#ifndef JSON_SUBOBJNAME_BODY
#define JSON_SUBOBJNAME_BODY    "body"
#endif

#ifndef JSON_KEYNM_CMD
#define JSON_KEYNM_CMD          "cmd"
#endif

#ifndef JSON_KEYNM_URL
#define JSON_KEYNM_URL          "url"
#endif

#ifndef JSON_KEYNM_TRID
#define JSON_KEYNM_TRID         "trid"
#endif

#ifndef JSON_KEYNM_FUNC
#define JSON_KEYNM_FUNC         "function"
#endif

#ifndef JSON_KEYNM_DATA
#define JSON_KEYNM_DATA         "data"
#endif

#ifndef ROT_CONF
#define ROT_CONF            "conf"
#endif

#ifndef ROT_DCONFILE
#define ROT_DCONFILE        "monD.conf"
#endif

#ifndef ROT_LOGDIR
#define ROT_LOGDIR          "logs"
#endif

#ifndef ROT_LOGFILE2
//#define ROT_LOGFILE2        "kms_watchdog_work_daemon.log"
#define ROT_LOGFILE2		"kms_watchdog_main_daemon.log"
#endif

#ifndef DOCK_JWT_KEY_STATE
#define DOCK_JWT_KEY_STATE "State"
#endif

#ifndef DOCK_JWT_KEY_STATUS
#define DOCK_JWT_KEY_STATUS "Status"
#endif

#ifndef DOCK_JWT_KEY_RUNNING
#define DOCK_JWT_KEY_RUNNING "Running"
#endif

#ifndef DOCK_JWT_KEY_PAUSED
#define DOCK_JWT_KEY_PAUSED  "Paused"
#endif

#ifndef DOCK_JWT_KEY_RESTARTING
#define DOCK_JWT_KEY_RESTARTING "Restarting"
#endif

#ifndef DOCK_JWT_KEY_ID
#define DOCK_JWT_KEY_ID  "Id"
#endif

#ifndef MOND_LISTEN_PORT
#define MOND_LISTEN_PORT "MOND_LISTEN_PORT"
#endif

#ifndef MOND_SERVER_IPADDR
#define MOND_SERVER_IPADDR "MOND_SERVER_IPADDR"
#endif

#ifndef MOND_DIR_LOG
#define MOND_DIR_LOG "MOND_DIR_LOG"
#endif

#ifndef MOND_BACKDIR_LOG
#define MOND_BACKDIR_LOG "MOND_BACKDIR_LOG"
#endif

#ifndef IDENT_DEFAULT
#define IDENT_DEFAULT "MOND_LOG"
#endif

#ifndef MOND_ROTSIZE_LOGFILE
#define MOND_ROTSIZE_LOGFILE "MOND_ROTSIZE_LOGFILE"
#endif

#ifndef MOND_ROTCNT_LOGFILE
#define MOND_ROTCNT_LOGFILE "MOND_ROTCNT_LOGFILE"
#endif

#ifndef MOND_ROTATE_ENABLE
#define MOND_ROTATE_ENABLE "MOND_ROTATE_ENABLE"
#endif

#ifndef MOND_WATCHDOG_ENABLE
#define MOND_WATCHDOG_ENABLE  "MOND_WATCHDOG_ENABLE"
#endif

#ifndef MOND_TARGET_CONTAINER
#define MOND_TARGET_CONTAINER   "MOND_TARGET_CONTAINER"
#endif

#ifndef MOND_TARGET_DAEMON
#define MOND_TARGET_DAEMON      "MOND_TARGET_DAEMON"
#endif

#ifndef MOND_DOCKER_URL
#define MOND_DOCKER_URL		"MOND_DOCKER_URL"
#endif

#ifndef MOND_LOG_LASTDATE
#define MOND_LOG_LASTDATE	"MOND_LOG_LASTDATE"
#endif

//<SIZE>
#ifndef NULLC
#define NULLC 0x00
#endif

#ifndef E_RET
#define E_RET -1
#endif

#ifndef BOOL
#define BOOL    int
#endif

#ifndef MAX_CMD_LEN
#define MAX_CMD_LEN 32
#endif

#ifndef MAX_URL_LEN
#define MAX_URL_LEN MAX_FULLPATH_SIZE
#endif

#ifndef MAX_TRID_LEN
#define MAX_TRID_LEN 9
#endif

#ifndef MAX_FUN_LEN
#define MAX_FUN_LEN 128
#endif

#ifndef MAX_BYDY_LEN
#define MAX_BYDY_LEN 4096
#endif

#ifndef MAX_HADERDATA_SIZE
#define MAX_HADERDATA_SIZE 1192
#endif

#ifndef MAX_TOKEN_SLOT
#define MAX_TOKEN_SLOT 10
#endif

#ifndef USE_TIMEOUT_CHECK
#define USE_TIMEOUT_CHECK 1
#endif

#ifndef DONT_USE_TIMEOUT_CHECK
#define DONT_USE_TIMEOUT_CHECK 2
#endif

#ifndef TIMEOUT_CHECK_SEC
#define TIMEOUT_CHECK_SEC 180
#endif

#ifndef MAX_Q_SIZE
#define MAX_Q_SIZE 21
#endif

#ifndef MAX_LOG_IDENT_SIZE
#define MAX_LOG_IDENT_SIZE 255
#endif

#ifndef MAX_LOG_BUF
#define MAX_LOG_BUF 4096//1024
#endif

#ifndef MAX_FULLPATH_SIZE
#define MAX_FULLPATH_SIZE  1024
#endif

#ifndef MAX_SLOG_SRC_NAME
#define MAX_SLOG_SRC_NAME   15
#endif

#ifndef MAX_SLOG_HOST_IP
#define MAX_SLOG_HOST_IP    15
#endif

#ifndef MAX_SLOG_SRC_NAME
#define MAX_SLOG_SRC_NAME   15
#endif

#ifndef MAX_SLOG_MESSAGE
#define MAX_SLOG_MESSAGE    4096//1023
#endif

#ifndef MAX_TARCONLISTBUF_SIZE
#define MAX_TARCONLISTBUF_SIZE  2048
#endif

#ifndef MAX_TARDAEMONLISTBUF_SIZE
#define MAX_TARDAEMONLISTBUF_SIZE       2048
#endif

#ifndef L_KEYWD
#define L_KEYWD 256
#endif

#ifndef L_TOKEN
#define L_TOKEN 1024
#endif

#ifndef L_LINEBUF
#define L_LINEBUF 2048
#endif

#ifndef MAX_UNIXTIME_DIGITS
#define MAX_UNIXTIME_DIGITS             13
#endif

#ifndef MAX_CONFNAME_LEN
#define MAX_CONFNAME_LEN                32
#endif

//<DEF>
#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef MODE_ON
#define MODE_ON                 "ON"
#endif

#ifndef MODE_OFF
#define MODE_OFF                "OFF"
#endif

#ifndef FUNC_ENABLE
#define FUNC_ENABLE             "YES"
#endif

#ifndef FUNC_DESABLE
#define FUNC_DESABLE            "NO"
#endif

//<ENUM>
enum _PARS_TYPE
{
    PARS_TYPE_KEYVALUE = 0,
    PARS_TYPE_ALLINONE,
    PSRS_TYPE_KEY_ALLINONE,
};

enum _monDConfIndex
{
        MOND_INDEX_DIR_LOG = 0,
        MOND_INDEX_BACKDIR_LOG,
        MOND_INDEX_ROTSIZE_LOGFILE,
        MOND_INDEX_ROTCNT_LOGFILE,
        MOND_INDEX_ROTATE_ENABLE,
        MOND_INDEX_WATCHDOGENABLE,
        MOND_INDEX_TAR_CONTAINER,
        MOND_INDEX_TAR_DAEMON,
        MOND_INDEX_DOCKER_URL,
        MOND_INDEX_LOG_LASTDATE,
        //MOND_INDEX_DOCKER_URL,
        MOND_INDEX_MAX
};

//<STRUCT>
struct rcopt_cfg
{

    char szMonDLogDir[MAX_FULLPATH_SIZE + 1];
    char szMonDLogBakDir[MAX_FULLPATH_SIZE + 1];
    int nMonDFileSize;
    int nMonDLogFileCount;

    char cMonRotateBakEnable;
    char szMonRotateBakDir[MAX_FULLPATH_SIZE + 1];
};
typedef struct rcopt_cfg rcopt_cfg_t;

typedef struct _SecureLog
{
    int32_t nLogType;
    int32_t nLogCode;
    int32_t nLogLevel;
    int32_t tCreateTime;
    int32_t tEventTime;
    int32_t nSourceCodeLine;
    char szSourceName[MAX_SLOG_SRC_NAME + 1];
    char szHostIP[MAX_SLOG_HOST_IP + 1];
    char szSourcePath[MAX_FULLPATH_SIZE + 1];
    char szMessage[MAX_SLOG_MESSAGE + 1];
} SecureLog_t;

struct memory   {

        char * response;
        size_t size;
};

struct WriteThis {
  const char *readptr;
  size_t sizeleft;
};

struct ContainerState {
        char Status[128];
        char ContainerID[1024];
        bool Running;
        bool Paused;
        bool Restarting;
};

typedef struct _tok
{
    char keywd[L_KEYWD];
    char value[L_TOKEN];
} s_token;

typedef struct _monDLogConf
{
        char szLogFolderNm[MAX_FULLPATH_SIZE];
        char szBackLogFolderNm[MAX_FULLPATH_SIZE];
        int32_t nLogFileSize;
        int32_t nLogFileCnt;
        char cRotateEnable;
        char cWatchDogEnable;
        char szTargetContainer[MAX_TARCONLISTBUF_SIZE];
        char szTargetDaemon[MAX_TARDAEMONLISTBUF_SIZE];
	char szDockerUrl[MAX_FULLPATH_SIZE];
        char szLogLastDate[MAX_UNIXTIME_DIGITS + 1];
} monDLogconf_t;

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

//<FUNCTION>
#define read_lock(fd, offset, whence, len) \
    lock_reg(fd, F_SETLK, F_RDLCK, offset, whence, len)
#define write_lock(fd, offset, whence, len) \
    lock_reg(fd, F_SETLK, F_WRLCK, offset, whence, len)
#define un_lock(fd, offset, whence, len) \
    lock_reg(fd, F_SETLK, F_UNLCK, offset, whence, len)

#define    RC_NLOADED              2
#define   RS_SO_STATE     7
#endif
