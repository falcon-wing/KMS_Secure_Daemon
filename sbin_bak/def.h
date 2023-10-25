#ifndef _DEF_H__
#define _DEF_H__
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

#define tell(x) lseek((x), 0, SEEK_CUR)

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

#ifndef L_KEYWD
#define L_KEYWD 256
#endif

#ifndef L_TOKEN
#define L_TOKEN 1024
#endif

#ifndef L_LINEBUF
#define L_LINEBUF 2048
#endif

#ifndef MAX_LOG_BUF
#define MAX_LOG_BUF 4096//1024
#endif

#ifndef MAX_FULLPATH_SIZE
#define MAX_FULLPATH_SIZE  1024
#endif

#ifndef BOOL
#define BOOL    int
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef E_RET
#define E_RET		-1
#endif

//#define NULL          0

#ifndef ROT_LOGDIR
#define ROT_LOGDIR          "logs"
#endif

#ifndef ROT_LOGFILE
#define ROT_LOGFILE         "monDlog.01"
#endif

#ifndef IDENT_DEFAULT
#define IDENT_DEFAULT "MOND_LOG"
#endif

#ifndef PRODUCT
#define PRODUCT "monDamon"
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

#ifndef MAX_TARCONLISTBUF_SIZE
#define MAX_TARCONLISTBUF_SIZE  2048
#endif

#ifndef MAX_TARDAEMONLISTBUF_SIZE
#define MAX_TARDAEMONLISTBUF_SIZE       2048
#endif

#ifndef MAX_SLOG_SRC_NAME
#define MAX_SLOG_SRC_NAME   15
#endif

#ifndef MAX_SLOG_HOST_IP
#define MAX_SLOG_HOST_IP    15
#endif

#ifndef MAX_SLOG_MESSAGE
#define MAX_SLOG_MESSAGE    4096//1023
#endif

#ifndef MAX_LOG_IDENT_SIZE
#define MAX_LOG_IDENT_SIZE 255
#endif

#ifndef MAX_SLOG_LINE_SIZE
#define MAX_SLOG_LINE_SIZE 4096//2047
#endif

#define NULLC 0x00

#ifndef MAINDAEMON_PRODUCTNAME
#define MAINDAEMON_PRODUCTNAME 	"monD"
#endif

#ifndef WORKDAEMON_PRODUCTNAME
#define WORKDAEMON_PRODUCTNAME  "ictk_wd"
#endif

#ifndef ROOT_PATH
#define ROOT_PATH   "/usr/local/ictk"
#endif

#ifndef ROT_CONF
#define ROT_CONF            "conf"
#endif

#ifndef ROT_DCONFILE
#define ROT_DCONFILE        "monD.conf"
#endif

#ifndef ROTD_PRODUCT_NAME
#define ROTD_PRODUCT_NAME "ROTDAMON"
#endif

#ifndef MAX_SLOG_LINE_SIZE
#define MAX_SLOG_LINE_SIZE 4096//2047
#endif

#ifndef IDENT_DEFAULT
#define IDENT_DEFAULT "MOND_LOG"
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

struct memory   {

        char * response;
        size_t size;
};

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

typedef struct _tok
{
    char keywd[L_KEYWD];
    char value[L_TOKEN];
} s_token;

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
        MOND_INDEX_MAX
};

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

#endif
