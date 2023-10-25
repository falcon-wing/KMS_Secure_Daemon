#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/procfs.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/procfs.h>
#include <time.h>
#include <fcntl.h>
#include "monM_def.h"
#include "rot_utils.h"
#include "utils_file.h"

extern char g_szLogFilename[MAX_FULLPATH_SIZE + 1];
extern char g_szLockFilename[MAX_FULLPATH_SIZE + 1];
extern char *g_pcSERVER_ADDR;
extern int g_nInitSecureLog;
extern int g_nMaxLogSize;
extern int g_nMaxLogFileCount;
extern int g_nRCLogRotate;
extern char g_szIdent[MAX_LOG_IDENT_SIZE + 1];

bool NeedUpdateDate(/*char * szData*/ );

int do_saverotlog(int nErrLevel, int nLogType, const char *file, int line,char *szErrMsg)
{
    int ret = TRUE;

    SecureLog_t tSecureLog;

    if ((nErrLevel == LV_DEBUG))
    {
        return TRUE;
    }

    tSecureLog.nLogType = nLogType;
    tSecureLog.nLogCode = 0;
    tSecureLog.nLogLevel = nErrLevel;
    tSecureLog.tCreateTime = 0;
    tSecureLog.tEventTime = get_ctime();
    tSecureLog.nSourceCodeLine = line;
    strncpy(tSecureLog.szSourceName, PRODUCT, MAX_SLOG_SRC_NAME);
    strncpy(tSecureLog.szSourcePath, file,MAX_FULLPATH_SIZE);
    tSecureLog.szSourceName[MAX_SLOG_SRC_NAME] = '\0';

    if (g_pcSERVER_ADDR != NULL)
    {
        strncpy(tSecureLog.szHostIP, g_pcSERVER_ADDR, MAX_SLOG_HOST_IP);
        tSecureLog.szHostIP[MAX_SLOG_HOST_IP] = '\0';
    }
    else
        tSecureLog.szHostIP[0] = '\0';

    strncpy(tSecureLog.szMessage, szErrMsg, MAX_SLOG_MESSAGE);
    tSecureLog.szMessage[MAX_SLOG_MESSAGE] = '\0';

    ret = SaveRotLog2(0, &tSecureLog);

    return ret;

}

static const char *level_strings[] = {
  "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"
};

char * make_log_msg(int msgType, char* remoteAddr, char * trid, char* funtion, char * status, char * LogMsg )
{
	char * sRet = NULL;
	char szLogMsg[MAX_SLOG_MESSAGE] = {0};
	char szType[8 + 1] = {0};
	if (msgType == 0 )		{sprintf (szType, "REQ");}
	else				{sprintf (szType, "RES");}
	sprintf (szLogMsg, "[[%s][%s][%s][%s][%s][%s][%s]]", szType, remoteAddr, trid, funtion, "", status, LogMsg);
	sRet = (char *) malloc (strlen (szLogMsg));
	sprintf (sRet, "%s", szLogMsg);
	return sRet;
}

int SaveRotLog2(int nOption, SecureLog_t *pstSecureLog)
{
	int lock_fd = -1, log_fd = -1;
        time_t tTime = 0;
        char szSecureLog[MAX_SLOG_LINE_SIZE + 1], szSyslog[MAX_SLOG_LINE_SIZE + 1];

        if (g_nInitSecureLog == FALSE)
        {
                return -1;
        }

	 time_t t = time(NULL);
    	//ev->time = localtime(&t);

	char buf[64];
  	buf[strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&t))] = '\0';
	snprintf(szSecureLog, MAX_SLOG_LINE_SIZE + 1, "%s %-5s [%s]:%d: %s\n",
		level_strings[(int)pstSecureLog->nLogType],buf, pstSecureLog->szSourcePath, pstSecureLog->nSourceCodeLine, pstSecureLog->szMessage);

	if (g_szLogFilename[0] != '\0')
        {
#ifdef _OLD_LOCK
                if ((lock_fd = rot_file_getfilelock(g_szLockFilename, CREATE_MODE, LOCK_FILEMODE)) != -1)
#else	
		if ( (lock_fd = get_filelock()) != -1 )
#endif //_OLD_LOCK
	
                {
                        if ((log_fd = rot_file_open_ex_second(g_szLogFilename, O_CREAT | O_WRONLY | O_APPEND, 0600)) != -1)
                        {
                                write(log_fd, szSecureLog, strlen(szSecureLog));

				if (NeedUpdateDate() == true)
                                {
                                        close(log_fd);
                                        RotateLogFile();
                                }
                                else
                                {
					
                                        close(log_fd);
                                }

                        }
                }
                else
                {
                }
#ifdef _OLD_LOCK
#else
		if ( lock_fd != -1 )
                	free_filelock(lock_fd);
#endif
        }
	else
        {
        }
#ifdef _OLD_LOCK
        if (lock_fd != -1)
                rot_file_unlock(lock_fd);
#endif
        return TRUE;

}

int SaveDLog(int nLogType, int nOption, SecureLog_t * pstSecureLog)
{
	int ret = 0;
	char szSecureLog[MAX_SLOG_LINE_SIZE + 1], szSyslog[MAX_SLOG_LINE_SIZE + 1];


	//DB_LOGFILE
	return ret;
}

int SaveRotLog(int nOption, SecureLog_t *pstSecureLog)
{
        int lock_fd = -1, log_fd = -1;
        time_t tTime = 0;
        char szSecureLog[MAX_SLOG_LINE_SIZE + 1], szSyslog[MAX_SLOG_LINE_SIZE + 1];

        if (g_nInitSecureLog == FALSE)
        {
                return -1;
        }

        time(&tTime);

        pstSecureLog->tCreateTime = tTime;

        snprintf(szSecureLog, MAX_SLOG_LINE_SIZE + 1, "%d\t%d\t%d\t%d\t%d\t%s\t%s\t%s\n",
                (int)pstSecureLog->nLogType, (int)pstSecureLog->nLogCode, (int)pstSecureLog->nLogLevel,
                (int)pstSecureLog->tCreateTime, (int)pstSecureLog->tEventTime, pstSecureLog->szSourceName,
                pstSecureLog->szHostIP, pstSecureLog->szMessage);

        if (g_szLogFilename[0] != '\0')
        {

                if ((lock_fd = rot_file_getfilelock(g_szLockFilename, CREATE_MODE, LOCK_FILEMODE)) != -1)
                {
                        if ((log_fd = rot_file_open_ex_second(g_szLogFilename, O_CREAT | O_WRONLY | O_APPEND, 0600)) != -1)
                        {
                                write(log_fd, szSecureLog, strlen(szSecureLog));
				/*
                                if (tell(log_fd) > g_nMaxLogSize)
                                {
                                        close(log_fd);
                                        RotateRotLogFile();
                                }
                                else
                                {
                                        close(log_fd);
                                }
				*/
				if (NeedUpdateDate())
				{
					close(log_fd);
					//RotateLogFile();
				}
				else
				{
					close(log_fd);
				}
                        }
                }
                else
                {
                }
        }
	else
        {
        }

        if (lock_fd != -1)
                rot_file_unlock(lock_fd);

        return TRUE;
}

int do_rotlog(char *fn, int level, int logtype, const char *file, int line,const char *fmt, ...)
{
    va_list ap;
    char str[MAX_LOG_BUF*4];
    int len;
/*
    if (NeedUpdateDate() == true )
    {
	RotateLogFile();
    }
*/
    pid_t thispid = getpid();

    snprintf(str, MAX_LOG_BUF *4, " ");

    len = strlen(str);

    va_start(ap, fmt);
    vsnprintf(str + len, (MAX_LOG_BUF *4) - len, fmt, ap);
    str[(MAX_LOG_BUF*4) - 1] = '\0';


    do_saverotlog(level, logtype,file,line ,str);

    va_end(ap);
}

int RotateRotLogFile(void)
{

    int i, nLen, fd, nRet;
    static char szBaseFilename[NAME_MAX + 1];
    static char szOldFilename[NAME_MAX + 1], szNewFilename[NAME_MAX + 1];
    char szBackupFileName[NAME_MAX + 1] = {
        0,
    };
    char szRcConfigPath[PATH_MAX + 1];
    char szDateTime[40] = {
        0,
    };
    rcopt_cfg_t stRCOpt;

    nLen = strlen(g_szLogFilename);
    strncpy(szBaseFilename, g_szLogFilename, nLen - 2);
    szBaseFilename[nLen - 2] = '\0';
    

    //time_t ptmTime = time(NULL);
    time_to_str(time(NULL), szDateTime);
    //sprintf (szDateTime , "%04d-%02d-%02d", ptmTime->tm_year + 1900, ptmTime->tm_mon + 1, ptmTime->tm_mday);

    snprintf(szNewFilename, sizeof(szNewFilename), "%s%02d", szBaseFilename, g_nMaxLogFileCount);

    if (g_nRCLogRotate == 0)
    {
        if (access(szNewFilename, F_OK) == 0)
            return 0;
    }

    rot_unlink(szNewFilename);

    for (i = g_nMaxLogFileCount - 1; i > 0; i--)
    {
        snprintf(szOldFilename, sizeof(szOldFilename), "%s%02d", szBaseFilename, i);
        snprintf(szNewFilename, sizeof(szNewFilename), "%s%02d", szBaseFilename, i + 1);
        rename(szOldFilename, szNewFilename);
        // rot_rename(szOldFilename, szNewFilename);
    }

    if ((fd = rot_file_open_ex_second(g_szLogFilename, O_CREAT | O_RDONLY, 0600)) >= 0)
        close(fd);

    return 0;
}
#ifdef _USE_LOG_FUNC
/*
*
*/
struct tm * get_lasttime(int nLastTime)
{
	time_t _time;
	_time = nLastTime;

	return localtime(&_time);
}

struct tm * get_nowtime()
{
	time_t _time;
	_time = time(NULL);

	return localtime(&_time);
}

bool NeedUpdateDate(/*char * szData*/ )
{	
	int nBeforLastDate = 0, nNewLastDate = 0;
	char szErrMsg[1024] = {0};
	char sData[MAX_UNIXTIME_DIGITS + 1] = {0};
        memset (&sData, 0x00 , sizeof (sData));
        sprintf (sData, "%s",get_conf_type_of_string(MOND_INDEX_LOG_LASTDATE,szErrMsg));

	nBeforLastDate = atoi(sData);

	struct tm * lasttime = get_lasttime(nBeforLastDate);
	struct tm * nowtime = get_nowtime();
	
	if (((int)lasttime->tm_mday) < ((int) nowtime->tm_mday))
	{
		return true;
	}
	
	return false;
}
#endif

int RotateLogFile(void )
{
	int i, nLen, fd;
	char szOrgLogFilename[MAX_FULLPATH_SIZE + 1] = {0};
	static char szBaseFilename[NAME_MAX + 1], szBackupFilename[NAME_MAX + 1];
	static char szOldFilename[NAME_MAX + 1], szNewFilename[NAME_MAX + 1];
	char szDateTime[40] = {0};
	char sData[MAX_UNIXTIME_DIGITS + 1] = {0};
	char szErrMsg[1024];

	time_t tTime = time(NULL);
	struct tm * ptmTime = localtime(&tTime);
	
        sprintf (szDateTime , "%04d-%02d-%02d", ptmTime->tm_year + 1900, ptmTime->tm_mon + 1, ptmTime->tm_mday);

        sprintf (sData, "%s",get_conf_type_of_string(MOND_INDEX_LOG_LASTDATE,szErrMsg));
	
	strncpy (szBaseFilename, g_szLogFilename, strlen(g_szLogFilename) - 4);
	snprintf (szNewFilename, sizeof (szNewFilename), "%s_%s.log", szBaseFilename, sData);

	rot_unlink(szNewFilename);
	rename (g_szLogFilename, szNewFilename);

	if ((fd = rot_file_open_ex_second(g_szLogFilename, O_CREAT | O_RDONLY, 0600)) >= 0 )
		close (fd);

	set_conf_type_of_string(MOND_INDEX_LOG_LASTDATE, szDateTime, szErrMsg);
	return 0;
}

int InitRotLog(char *szIdent, char *szFilename, int _nMaxLogSize, int _nMaxLogFileCount, int nRotate)
{
    static char szBaseFilename[MAX_FULLPATH_SIZE + 1];
    int nLen;

    if ((szIdent == NULL) || (szIdent[0] == '\0'))
        return -1;

    if ((szFilename != NULL) && (szFilename[0] != '\0'))
    {
        if ((_nMaxLogSize < 1) || (_nMaxLogFileCount < 1))
            return -1;

        if (nRotate != 0 && nRotate != 1)
            return -1;
    }

    strncpy(g_szIdent, szIdent, MAX_LOG_IDENT_SIZE); /* syslog ident °ª ¼³Á¤. */
    g_szIdent[MAX_LOG_IDENT_SIZE] = '\0';

    if ((szFilename != NULL) && (szFilename[0] != '\0'))
    {
        strncpy(g_szLogFilename, szFilename, MAX_FULLPATH_SIZE);
        g_szLogFilename[MAX_FULLPATH_SIZE] = '\0';

        g_nMaxLogSize = _nMaxLogSize;
        g_nMaxLogFileCount = _nMaxLogFileCount;

        nLen = strlen(szFilename);
        strncpy(szBaseFilename, szFilename, nLen - 3);
        szBaseFilename[nLen - 2] = '\0';

        snprintf(g_szLockFilename, MAX_FULLPATH_SIZE + 1, "%slock", szBaseFilename);

        g_nRCLogRotate = nRotate;
    }

    g_nInitSecureLog = 1;

    return 0;
}
