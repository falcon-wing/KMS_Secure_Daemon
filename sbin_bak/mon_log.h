#ifndef _MON_LOG_H__
#define _MON_LOG_H__

#include <stdlib.h>
#include <stdio.h>
//#include "rotmond_def.h"
//#include "monM_def.h"
#include "def.h"

int InitRotLog(char *szIdent, char *szFilename, int _nMaxLogSize, int _nMaxLogFileCount, int nRotate);
int RotateRotLogFile(void);
int SaveRotLog(int nOption, SecureLog_t *pstSecureLog);
//char * make_log_msg(int msgType, char* remoteAddr, char * trid, char * status, char * szLogMsg );
char * make_log_msg(int msgType, char* remoteAddr, char * trid, char* funtion, char * status, char * LogMsg );
int do_saverotlog(int nErrLevel, int nLogType, char *szErrMsg);

//#define db_log(fmt, ...) do_rotlog(ROTPRODUCT_NAME, 1, fmt, __FILE__,__LINE__, __VA_ARGS__)

#endif  //_MON_LOG_H__
                                    
