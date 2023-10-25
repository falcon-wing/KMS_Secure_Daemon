#ifndef _MON_LOG_H__
#define _MON_LOG_H__

#include <stdlib.h>
#include <stdio.h>
#include "def.h"

int InitRotLog(char *szIdent, char *szFilename, int _nMaxLogSize, int _nMaxLogFileCount, int nRotate);
int RotateRotLogFile(void);
int SaveRotLog(int nOption, SecureLog_t *pstSecureLog);
char * make_log_msg(int msgType, char* remoteAddr, char * trid, char* funtion, char * status, char * LogMsg );
int do_saverotlog(int nErrLevel, int nLogType, char *szErrMsg);
void FreeFileLock(int fd);
#endif  //_MON_LOG_H__
                                    
