#ifndef _DAEMON_FUNC_H__
#define _DAEMON_FUNC_H__

//daemon_func

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rot_sock.h"

int pars_data_objs(const char *_pData, char **_ppData);
//char *make_response_json(char *_sCmd, char *_sUrl, char *_sTrid, char *_sfunc, char *_sData, int _nType);
char *make_response_json(char *_sCmd, char *_sUrl, char *_sTrid, char *_sfunc,char * _skeyName,char *_sData, int _nType);
char *make_response_json_v2(char *_sCmd, char *retCode, char *_sTrid, char *_retMessage, char * _skeyName, char *_sData, int _nType);
int process_cmd(LPSOCKETINFO new_sockfd);




#endif
