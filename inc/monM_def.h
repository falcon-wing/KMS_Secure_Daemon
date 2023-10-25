#ifndef _MONM_DEF_H__
#define _MONM_DEF_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <json-c/json.h>
#include <stdbool.h>

#define tell(x) lseek((x), 0, SEEK_CUR)

#ifndef REQ_MSG
#define REQ_MSG  0
#endif

#ifndef RES_MSG
#define RES_MSG  1
#endif

#ifndef MAX_ARG_NUM
#define MAX_ARG_NUM             64
#endif

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
#endif//

#ifndef LOCK_FILEMODE
#define LOCK_FILEMODE 02600
#endif

#ifndef NULLC
#define NULLC 0x00
#endif

#ifndef E_RET
#define E_RET -1
#endif

#ifndef BOOL
#define BOOL    int
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

#ifndef MAINDAEMON_PRODUCTNAME
#define MAINDAEMON_PRODUCTNAME  "rotD"
#endif

#ifndef WATCHDOG_PROGUCTNAME
#define WATCHDOG_PROGUCTNAME   "wd_worker"//"ictk_wd"
#endif 

#ifndef ROOT_PATH
#define ROOT_PATH   "/usr/local/ictk"
#endif

enum MOND_COMMAND
{
	MOND_COMM_CONTAINER = 0,
	MOND_COMM_PID	,
	MOND_COMM_WD	,
	MOND_COMM_SOCKCLIENT ,
	MOND_COMM_MAX
};

struct memory	{

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

enum _PARS_TYPE
{
    PARS_TYPE_KEYVALUE = 0,
    PARS_TYPE_ALLINONE,
    PSRS_TYPE_KEY_ALLINONE,
    PSRS_TYPE_BODY_NULL,
    PSRS_TYPE_STRING,
};

#ifndef MAX_BUF_SIZE
#define MAX_BUF_SIZE        4096
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

#ifndef MAX_CMD_LEN
#define MAX_CMD_LEN 32
#endif

#ifndef MAX_URL_LEN
#define MAX_URL_LEN MAX_FULLPATH_SIZE
#endif

#ifndef ROT_LOGDIR
#define ROT_LOGDIR          "logs"
#endif

#ifndef ROT_LOGFILE
#define ROT_LOGFILE         "rotDlog.01"
#endif

#ifndef ROT_LOGFILE3
#define ROT_LOGFILE3         "kms_secure_daemon.log"
#endif

#ifndef ROT_LOGFILE2
#define ROT_LOGFILE2	    "kms_watchdog_main_daemon.log"
#endif

#ifndef DB_LOGFILE
#define DB_LOGFILE	    "kms_watchdog_comm_daemon.log"
#endif

#ifndef DBG_LOGFILE
#define DBG_LOGFILE	    "kms_watchdog_main_daemon_dbg.log"
#endif

#ifndef PAM_LOGFILE
#define PAM_LOGFILE	    "kms_pam_system.log"
#endif

#ifndef ROT_CONF
#define ROT_CONF            "conf"
#endif

#ifndef ROT_DCONFILE
#define ROT_DCONFILE        "rotD.conf"
#endif

#ifndef ETC_DIR
#define ETC_DIR		    "etc"
#endif

#ifndef ROT_DLOCKPIDFILE
#define ROT_DLOCKPIDFILE    "rotD.pid"
#endif


#ifndef PRODUCT
#define PRODUCT "rotDamon"
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef LV_DEBUG
#define LV_DEBUG 0
#endif

#ifndef LV_INFO
#define LV_INFO 2
#endif

#ifndef LV_ERR
#define LV_ERR 1
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

typedef struct _tok
{
    char keywd[L_KEYWD];
    char value[L_TOKEN];
} s_token;

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

#ifndef MAX_UNIXTIME_DIGITS
#define MAX_UNIXTIME_DIGITS		13
#endif

#ifndef MAX_CONFNAME_LEN		
#define MAX_CONFNAME_LEN		32
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


enum _rotDConfIndex
{
    ROTD_INDEX_DIR_LOG = 0,
    ROTD_INDEX_BACKDIR_LOG,
    ROTD_INDEX_ROTSIZE_LOGFILE,
    ROTD_INDEX_ROTCNT_LOGFILE,
    ROTD_INDEX_ROTATE_ENABLE,
    ROTD_INDEX_MAX
};

typedef struct _RotConf
{
        char szLogFolderNm[MAX_FULLPATH_SIZE];
        char szBackLogFolderNm[MAX_FULLPATH_SIZE];
        int32_t nLogFileSize;
        int32_t nLogFileCnt;
        char cRotateEnable;
} rotDconf_t;


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

struct _ROT_CMD
{
    char sCmd[MAX_CMD_LEN];
    char sUrl[MAX_URL_LEN];
    char sTrid[MAX_TRID_LEN];
    char sFunction[MAX_FUN_LEN];
    //char sData[MAX_BYDY_LEN];
   // json_object * pBodyObject;
    json_object * pDataObject;
};

typedef struct _ROT_CMD ROT_CMD;

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

#ifndef ROTD_PRODUCT_NAME
#define ROTD_PRODUCT_NAME "ROTDAMON"
#endif

#ifndef MAX_SLOG_LINE_SIZE
#define MAX_SLOG_LINE_SIZE 4096//2047
#endif

#ifndef IDENT_DEFAULT
#define IDENT_DEFAULT "ROTD_LOG"
#endif

#ifndef PAM_ACL_CONF
#define PAM_ACL_CONF    "/etc/security/rotPam.conf"
//#define PAM_ACL_CONF    "/etc/.rotpam/rotPam.conf"
#endif

#ifndef PAM_ACL_RULE_DIR
#define PAM_ACL_RULE_DIR "/etc/.rotpam/"
#endif

#ifndef PAM_ACL_USERRULE_FILE
#define PAM_ACL_USERRULE_FILE   "rotPamUser.rule"
#endif

#ifndef PAM_ACL_GROUPRULE_FILE
#define PAM_ACL_GROUPRULE_FILE  "rotPamGroup.rule"
#endif

#ifndef PAM_ACL_DEFAULTRULE_FILE
#define PAM_ACL_DEFAULTRULE_FILE        "rulePamDefault.rule"
#endif

#ifndef PAM_ACL_CONF
#define PAM_ACL_CONF    "/etc/security/rotPam.conf"
#endif

#ifndef JSON_KEYNM_RTNCODE
#define JSON_KEYNM_RTNCODE         "rtnCode"
#endif

#ifndef JSON_KEYNM_RTNMESSAGE
#define JSON_KEYNM_RTNMESSAGE         "rtnMessage"
#endif


#ifndef ROT_PAM_OP_MODE
#define ROT_PAM_OP_MODE         "ROT_PAM_OP_MODE"
#endif

#ifndef ROT_PAM_MFA_MODE
#define ROT_PAM_MFA_MODE        "ROT_PAM_MFA_MODE"
#endif

#ifndef ROT_ROTD_OP_MODE
#define ROT_ROTD_OP_MODE        "ROT_ROTD_OP_MODE"
#endif

#ifndef ROT_SYSMON_OP_MODE
#define ROT_SYSMON_OP_MODE      "ROT_SYSMON_OP_MODE"
#endif

#ifndef ROT_FW_OP_MODE
#define ROT_FW_OP_MODE          "ROT_FW_OP_MOE"
#endif

#ifndef MODE_ON
#define MODE_ON                 "ON"
#endif

#ifndef MODE_OFF
#define MODE_OFF                "OFF"
#endif



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

#define CMD_PAM_BASE_V2 500100
//#define CMD_PAM_BASE 500100
#define CMD_PAM_GET_OP_MODE             CMD_PAM_BASE_V2 + 1        //500101
#define CMD_PAM_SET_OP_MODE             CMD_PAM_BASE_V2 + 2        //500102
#define CMD_PAM_GET_RULE                CMD_PAM_BASE_V2 + 3        //500103
#define CMD_PAM_SET_RULE                CMD_PAM_BASE_V2 + 4        //500104
#define CMD_PAM_ADD_RULE                CMD_PAM_BASE_V2 + 5        //500105
#define CMD_PAM_DEL_RULE                CMD_PAM_BASE_V2 + 6        //500106
//#define CMD_PAM_GET_LOGS              CMD_PAM_BASE_V2 + 5

#define CMD_PAM_GET_MFA_ACT             CMD_PAM_BASE_V2 + 7        //500105
#define CMD_PAM_SET_MFA_ACT             CMD_PAM_BASE_V2 + 8        //500106

#define CMD_FW_BASE 500400
#define CMD_FW_ADD_RULE                 CMD_FW_BASE     + 1  
#define CMD_FW_DEL_RULE                 CMD_FW_BASE     + 2
#define CMD_FW_INS_RULE                 CMD_FW_BASE     + 3
#define CMD_FW_SET_RULE                 CMD_FW_BASE     + 4
#define CMD_FW_INS_RULE_WITHOUT_DEF     CMD_FW_BASE     + 5


#define CMD_PAM_BASE 500300
#ifndef CMD_MOND_GET_MODDE
#define CMD_MOND_GET_MODDE      CMD_PAM_BASE + 1   //500301
#endif

#ifndef CMD_MOND_SET_MODDE
#define CMD_MOND_SET_MODDE      CMD_PAM_BASE + 2        //500302
#endif

#ifndef CMD_MOND_GET_TARCONTAINERLIST
#define CMD_MOND_GET_TARCONTAINERLIST   CMD_PAM_BASE + 3        //500303
#endif

#ifndef CMD_MOND_SET_TARCONTAINERLIST
#define CMD_MOND_SET_TARCONTAINERLIST   CMD_PAM_BASE + 4        //500304
#endif

#ifndef CMD_MOND_GET_TARDAEMONLIST
#define CMD_MOND_GET_TARDAEMONLIST      CMD_PAM_BASE + 5        //500305
#endif

#ifndef CMD_MOND_SET_TARDAEMONLIST
#define CMD_MOND_SET_TARDAEMONLIST      CMD_PAM_BASE + 6        //500306
#endif

#ifndef CMD_MOND_GET_CPUINFO
#define CMD_MOND_GET_CPUINFO            CMD_PAM_BASE + 7        //500307
#endif

#ifndef CMD_MOND_GET_MEMINFO
#define CMD_MOND_GET_MEMINFO            CMD_PAM_BASE + 8        //500308
#endif

#ifndef CMD_MOND_GET_DISKIOINFO
#define CMD_MOND_GET_DISKIOINFO         CMD_PAM_BASE + 9        //500309
#endif
// CPU 정보
/*
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
*/
// MEM 정보
typedef struct _meminfo
{
    FILE *fp;                // 파일 스트림 포인터
    char memname[50];        // MEM 구분
    long long mem_info;      // MEM 수치
} MEM_P;

// mount 정보
struct f_size
{
    long blocks;
    long avail;
    long used;
};

typedef struct _mountinfo
{
    FILE *fp;                // 파일 스트림 포인터
    char devname[80];        // 장치 이름
    char mountdir[80];       // 마운트 디렉토리 이름
    char fstype[12];         // 파일 시스템 타입
    struct f_size size;      // 파일 시스템의 총크기/사용율
} MOUNT_P;

// diskstat 정보
typedef struct _diskioinfo
{
    FILE *fp;             // 파일 스트림 포인터
    char diskname[80];    // 장치 이름
    long red_compl;       // 1) 완료된 읽기
    long red_merge;       // 2) 합산된 읽기
    long red_sectr;       // 3) 읽기 성공한 섹터총량
    long red_milsc;       // 4) 밀리세컨드 동안 읽기 총계
    long wrt_comp;        // 5) 완료된 쓰기
    long wrt_merg;        // 6) 합산된 쓰기
    long wrt_sect;        // 7) 쓰기 성공한 섹터 총량
    long wrt_mils;        // 8) 밀리세컨드 동안 쓰기 총계
    long io_c_prc;        // 9) 현재 진행중인 입출력
    long io_comp;         // 10) 밀리세컨드 동안 입출력
    long io_mils;         // 11) 밀리세컨드 동안 입출력 가중치
    char temp1[50];        // 필요없는정보
} DISKSTAT_P;

// partition 정보
typedef struct _partinfo
{
    FILE *fp;             // 파일 스트림 포인터
    char partname[80];    // 장치 이름
    char temp1[50];       // 필요없는정보
} PARTITION_P;

#ifndef LOG_FORMAT_DATA
#define LOG_FORMAT_DATA		"[[%s][%s][%s][%s][%s][%s][%s]]"
#endif

typedef enum _PAM_RULE_INDEX
{
    PAM_RULE_INDEX_MODE = 0,
    PAM_RULE_INDEX_ADDR ,
    PAM_RULE_INDEX_DOMAIN,
    PAM_RULE_INDEX_ACCOUNT,
    PAM_RULE_INDEX_GUID,
    PAM_RULE_INDEX_MACADDR,
    PAM_RULE_INDEX_MAX
}PAM_RULE_INDEX;


typedef struct _PAM_RULE_INFO
{
    char szMode[8];
    char szIpAddr[128];
    char szDomain[128];
    char szAccount[128];
    char szGuid[8];
    char szMacAddr[128];
}PAM_RULLE_INFO;

#endif
