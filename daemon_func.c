#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <syslog.h>
#include <strings.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <json-c/json.h>
#include <ctype.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>

#include "rot_sock.h"
#include "mon_log.h"
#include "mon_log2.h"
#include "daemon_func.h"
#include "monM_def.h"

extern char g_szRootPath[MAX_FULLPATH_SIZE + 1];
char g_szLogPath[MAX_FULLPATH_SIZE] = {0};

/*
 *
 */
json_object *get_cmd_at_jsondata(json_object *jsRootData)
{
    return json_object_object_get(jsRootData, JSON_KEYNM_CMD);
}

/*
 *
 */
json_object *get_targeturl_at_jsondata(json_object *jsTargetObj)
{
    return json_object_object_get(jsTargetObj, JSON_KEYNM_URL);
}

/*
 *
 */
json_object *get_trid_at_jsondata(json_object *jsHeaderObj)
{
    return json_object_object_get(jsHeaderObj, JSON_KEYNM_TRID);
}

/*
 *
 */
json_object *get_function_at_jsondata(json_object *jsHeaderObj)
{
    return json_object_object_get(jsHeaderObj, JSON_KEYNM_FUNC);
}

/*
 *
 */
json_object *get_bodydata_at_jsondata(json_object *jsBodyObj)
{
    return json_object_object_get(jsBodyObj, JSON_KEYNM_DATA);
}

/*
 *
 */
int pars_key_n_value(char *_sData, char *_ckey, char *_cvalue)
{
    _ckey = strtok(_sData, "|");
    _cvalue = strtok(NULL, "|");
    return TRUE;
}

/*
 *
 */
char *mystrsep(char **stringp, const char *delim)
{
    char *start = *stringp;
    char *p;

    p = (start != NULL) ? strpbrk(start, delim) : NULL;

    if (p == NULL)
    {
        *stringp = NULL;
    }
    else
    {
        *p = '\0';
        *stringp = p + 1;
    }

    return start;
}

/*
 *
 */
int pars_data_objs(const char *_pData, char **_ppData)
{
    int ret = 0, nIndex = 0;
    char *pData = NULL;
    char szData[MAX_BYDY_LEN] = {0};
    snprintf(szData, MAX_BYDY_LEN, "%s", _pData);
    pData = strtok(szData, ";");

    while (pData != NULL)
    {
        _ppData[nIndex] = pData;
        pData = strtok(NULL, ";");
        nIndex++;
    }

    ret = nIndex;
    return ret;
}

char *make_response_json_v2(char *_sCmd, char *retCode, char *_sTrid, char *_retMessage, char * _skeyName, char *_sData, int _nType)
{
    int nCnt, i = 0;
    char *strRespJson = NULL;
    char *ptok, *ptoksub, *pDataItem, *pDataItemValue;
    char *szItemData[MAX_FULLPATH_SIZE] = {0};
    char *szData[32];
    strRespJson = malloc(MAX_HADERDATA_SIZE + MAX_BYDY_LEN);

    if (strRespJson == NULL)
    {
        // ERROR MSG
        return NULL;
    }

    memset(strRespJson, 0x00, MAX_HADERDATA_SIZE + MAX_BYDY_LEN);

    json_object *jsMainObj = json_object_new_object();
    json_object *jsheaderObj = json_object_new_object();
    json_object *jsbodyObj = json_object_new_object();

    json_object_object_add(jsheaderObj, JSON_KEYNM_TRID, json_object_new_string(_sTrid));
    json_object_object_add(jsheaderObj, JSON_KEYNM_RTNCODE, json_object_new_string(retCode));
    json_object_object_add(jsheaderObj, JSON_KEYNM_RTNMESSAGE, json_object_new_string(_retMessage));

    if (_nType == (int)PARS_TYPE_KEYVALUE)
    {
        nCnt = pars_data_objs(_sData, szData);
        for (i = 0; i < nCnt; i++)
        {
            pDataItem = strtok(szData[i], "|");

            do
            {
                pDataItemValue = strtok(NULL, "|");
            } while (FALSE);

            json_object_object_add(jsbodyObj, pDataItem, json_object_new_string(pDataItemValue));
        }
    }
    else if (_nType == (int)PSRS_TYPE_KEY_ALLINONE)
    {
        json_object_object_add(jsbodyObj, _skeyName, json_object_new_string(_sData));
    }
    else if (_nType == (int)PSRS_TYPE_BODY_NULL)
    {

    }
    else{
        //json_object_object_add(jsbodyObj, JSON_KEYNM_DATA, json_object_new_string(_sData));
    }

    json_object_object_add(jsMainObj, JSON_SUBOBJNAME_HEADER, jsheaderObj);
    if (_nType != (int)PSRS_TYPE_BODY_NULL)
    {
        json_object_object_add(jsMainObj, JSON_SUBOBJNAME_BODY, jsbodyObj);
    }

    snprintf(strRespJson, MAX_HADERDATA_SIZE + MAX_BYDY_LEN, "%s", json_object_get_string(jsMainObj));

    if (jsheaderObj != NULL)
    {
        json_object_object_del(jsheaderObj, JSON_SUBOBJNAME_HEADER);
    }

    if (jsbodyObj != NULL)
    {
        json_object_object_del(jsbodyObj, JSON_SUBOBJNAME_BODY);
    }
   
    return strRespJson;
}
/*
 *
 */
char *make_response_json(char *_sCmd, char *_sUrl, char *_sTrid, char *_sfunc, char * _skeyName, char *_sData, int _nType)
{
    int nCnt, i = 0;
    char *strRespJson = NULL;
    char *ptok, *ptoksub, *pDataItem, *pDataItemValue;
    char *szItemData[MAX_FULLPATH_SIZE] = {0};
    char *szData[32];
    strRespJson = malloc(MAX_HADERDATA_SIZE + MAX_BYDY_LEN);

    if (strRespJson == NULL)
    {
        // ERROR MSG
        return NULL;
    }

    memset(strRespJson, 0x00, MAX_HADERDATA_SIZE + MAX_BYDY_LEN);

    json_object *jsMainObj = json_object_new_object();
    json_object_object_add(jsMainObj, JSON_KEYNM_CMD, json_object_new_string(_sCmd));
    json_object *jsReqObj = json_object_new_object();
    json_object *jstargetObj = json_object_new_object();
    json_object *jsheaderObj = json_object_new_object();
    json_object *jsbodyObj = json_object_new_object();

    json_object_object_add(jstargetObj, JSON_KEYNM_URL, json_object_new_string(_sUrl));
    json_object_object_add(jsheaderObj, JSON_KEYNM_TRID, json_object_new_string(_sTrid));
    json_object_object_add(jsheaderObj, JSON_KEYNM_FUNC, json_object_new_string(_sfunc));

    if (_nType == (int)PARS_TYPE_KEYVALUE)
    {
        nCnt = pars_data_objs(_sData, szData);
        for (i = 0; i < nCnt; i++)
        {
            //do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "pars_data_objs Cnt = [%d][%s]", nCnt, szData[i]);

            pDataItem = strtok(szData[i], "|");

            do
            {
                pDataItemValue = strtok(NULL, "|");
            } while (FALSE);

	    json_object_object_add(jsbodyObj, pDataItem, json_object_new_string(pDataItemValue));
        }
    }
    else if (_nType == (int)PSRS_TYPE_KEY_ALLINONE)
    {
	json_object_object_add(jsbodyObj, _skeyName, json_object_new_string(_sData));
    }
    else{
        json_object_object_add(jsbodyObj, JSON_KEYNM_DATA, json_object_new_string(_sData));
    }

    json_object_object_add(jsReqObj, JSON_SUBOBJNAME_TAR, jstargetObj);
    json_object_object_add(jsReqObj, JSON_SUBOBJNAME_HEADER, jsheaderObj);
    json_object_object_add(jsReqObj, JSON_SUBOBJNAME_BODY, jsbodyObj);
    json_object_object_add(jsMainObj, JSON_SUBOBJNAME_REQ, jsReqObj);

    snprintf(strRespJson, MAX_HADERDATA_SIZE + MAX_BYDY_LEN, "%s", json_object_get_string(jsMainObj));

    if (jstargetObj != NULL)
    {
        json_object_object_del(jstargetObj, JSON_SUBOBJNAME_TAR);
    }

    if (jsheaderObj != NULL)
    {
        json_object_object_del(jsheaderObj, JSON_SUBOBJNAME_HEADER);
    }

    if (jsbodyObj != NULL)
    {
        json_object_object_del(jsbodyObj, JSON_SUBOBJNAME_BODY);
    }

    nCnt = json_object_object_length(jsReqObj);
    if (nCnt == 0 && jsReqObj != NULL)
    {
        json_object_object_del(jsReqObj, JSON_SUBOBJNAME_REQ);
    }

    return strRespJson;
}	

/*
 *
 */
int do_get_cpuinfo (LPSOCKETINFO new_sockfd, struct _ROT_CMD *rot_cmd, char * szresponsedata, char * szErrMsg)
{
        return 0;
}

/*
 *
 */
int do_get_meminfo (LPSOCKETINFO new_sockfd, struct _ROT_CMD *rot_cmd, char * szresponsedata, char * szErrMsg)
{
        return 0;
}

/*
 *
 */
int do_get_diskIOinfo (LPSOCKETINFO new_sockfd, struct _ROT_CMD *rot_cmd, char * szresponsedata, char * szErrMsg)
{
        return 0;
}

void init_log2()
{
	memset (g_szLogPath, 0x00 , sizeof (g_szLogPath));
	sprintf (g_szLogPath, "%s/%s/%s",g_szRootPath,ROT_LOGDIR,ROT_LOGFILE2);
}

void do_log(const char * fmt, ...)
{
        FILE * info_fp;
        va_list ap;
        va_start(ap, fmt);
        char szInfoLogPath[MAX_FULLPATH_SIZE + 1];
        char szBuf[2048 +1] = {0};

        vsprintf (szBuf, fmt, ap);
        va_end(ap);

        log_set_level(0);
        log_set_quiet(1);

//        sprintf (szInfoLogPath, "%s/%s/ictk_wd.01", ICTK_ROOT_PATH, "logs");
        info_fp = fopen (g_szLogPath, "a+");
        if (info_fp == NULL )
        {
		do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "do_log func...fail 1");
                return ;
        }

	do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "do_log func...0001");
        log_add_fp(info_fp, 2);
        log_info(szBuf);

        fclose (info_fp);
}
/*
 *
 */
int do_get_tarDaemonlist (LPSOCKETINFO new_sockfd, struct _ROT_CMD *_cmd, char * szresponsedata, char * szErrMsg)
{
	int rt = 0;
	char sData[MAX_CONFNAME_LEN + MAX_UNIXTIME_DIGITS];
	sprintf (sData, "watchd_target_darmons|%s", get_conf_type_of_string(MOND_INDEX_TAR_DAEMON, szErrMsg));

        make_response_json(_cmd->sCmd, _cmd->sUrl, _cmd->sTrid, _cmd->sFunction, NULL ,sData , 0);

        return 0;
}

/*
 *
 */
int do_set_tarDaemonlist (LPSOCKETINFO new_sockfd, struct _ROT_CMD *rot_cmd, char * szresponsedata, char * szErrMsg)
{
        char szIMode[4] = {0};
        char sData[2048] = {0};
        monDLogconf_t monDconf;
        snprintf (sData, MAX_FULLPATH_SIZE, "%s", json_object_get_string(   json_object_object_get( rot_cmd->pDataObject, "watchd_target_darmons")));

        get_monD_conf(&monDconf, szErrMsg);

        memset (monDconf.szTargetDaemon, 0x00, sizeof (monDconf.szTargetDaemon));

        sprintf (monDconf.szTargetDaemon, "%s", sData );
        set_monD_conf(monDconf, szErrMsg);

        return 0;
}

/*
 *
 */
int do_get_tarcontainerlist (LPSOCKETINFO new_sockfd, struct _ROT_CMD *_cmd, char * szresponsedata, char * szErrMsg)
{
	int ret = 0;
	char sData[MAX_CONFNAME_LEN + MAX_TARCONLISTBUF_SIZE];
	sprintf (sData, "watchd_target_containers|%s", get_conf_type_of_string(MOND_INDEX_TAR_CONTAINER, szErrMsg));

	make_response_json(_cmd->sCmd, _cmd->sUrl, _cmd->sTrid, _cmd->sFunction, NULL ,sData , 0);

        return 0;
}

/*
 *
 */
int do_set_tarcontainerlist (LPSOCKETINFO new_sockfd, struct _ROT_CMD *rot_cmd, char * szresponsedata, char * szErrMsg)
{
	char szIMode[4] = {0};
	char sData[2048] = {0};
	monDLogconf_t monDconf;
	snprintf (sData, MAX_FULLPATH_SIZE, "%s", json_object_get_string(   json_object_object_get( rot_cmd->pDataObject, "watchd_target_containers")));

	get_monD_conf(&monDconf, szErrMsg);

	memset (monDconf.szTargetContainer, 0x00, sizeof (monDconf.szTargetContainer));

	sprintf (monDconf.szTargetContainer, "%s", sData );
        set_monD_conf(monDconf, szErrMsg);

        return 0;
}

/*
 *
 */
int do_get_opmode(LPSOCKETINFO new_sockfd, struct _ROT_CMD *_cmd, char * szresponsedata, char * szErrMsg)
{
	char sData[MAX_CONFNAME_LEN + 8];
	sprintf (sData, "watchd_op_mode|%s", get_conf_type_of_string(MOND_INDEX_WATCHDOGENABLE, szErrMsg));

	make_response_json(_cmd->sCmd, _cmd->sUrl, _cmd->sTrid, _cmd->sFunction, NULL ,sData , 0);
	return 0;
}

/*
 *
 */
int do_set_opmode(LPSOCKETINFO new_sockfd, struct _ROT_CMD *rot_cmd, char * szresponsedata, char * szErrMsg)
{
	//MOND_WATCHDOG_ENABLE
	char szWatchDogMode[4] = {0};
	monDLogconf_t monDconf;
        //char szErrMsg [1024] = {0};
        memset (&monDconf, 0x00 , sizeof (monDconf));
	snprintf (szWatchDogMode, 4, "%s", json_object_get_string(   json_object_object_get( rot_cmd->pDataObject, "watchd_op_mode")));

        get_monD_conf(&monDconf, szErrMsg);

	if (strcmp (szWatchDogMode, FUNC_ENABLE) == 0 )
	{
		monDconf.cWatchDogEnable = 'Y';
	}
	else
	{
		monDconf.cWatchDogEnable = 'N';
	}

	set_monD_conf(monDconf, szErrMsg);

        return 0;
}

/*
 *
 */
#if USE_PROCESS_CMD
int process_cmd(LPSOCKETINFO new_sockfd)
{
	int ret = 0, nCnt = 0, iCommand = 0;
    	int nPamOpMode;
    	struct _ROT_CMD rot_cmd;
   	 char buf[MAX_BUF_SIZE] = {0};
    	char szPamMode[128] = {0};
    	char szSendData[MAX_BUF_SIZE] = {0};
    	char szSendBuf[MAX_HADERDATA_SIZE + MAX_BYDY_LEN] = {0};
    	char szResponseData[MAX_HADERDATA_SIZE + MAX_BYDY_LEN] = {0};
    	char szErrMsg[1024] = {0};

	do{
		if (read_data(new_sockfd, &rot_cmd) != TRUE)
		{
			do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "recv fail~~~~");

			perror("recv");
			exit(1);
		}

		iCommand = atoi(rot_cmd.sTrid);

		switch (iCommand )
		{
        case CMD_PAM_GET_OP_MODE:
        {
            do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "CMD_PAM_GET_OP_MODE call..");
        }
        break;
        case CMD_PAM_SET_OP_MODE:
        {
            do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "CMD_PAM_SET_OP_MODE call..");
        }
        break;
        case CMD_PAM_GET_RULE:
        {
            do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "CMD_PAM_GET_RULE call..");
        }
        break;
        case CMD_PAM_SET_RULE:
        {
            do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "CMD_PAM_SET_RULE call..");
        }
        break;
        case CMD_FW_ADD_RULE:
        {
            do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "CMD_FW_ADD_RULE call..");
        }
        break;
        case CMD_FW_DEL_RULE:
        {
            do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "CMD_FW_DEL_RULE call..");
        }
        break;
        case CMD_FW_SET_RULE:
        {
            do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "CMD_FW_SET_RULE call..");
        }
        break;

		case CMD_MOND_GET_MODDE:
			ret = do_get_opmode(new_sockfd, &rot_cmd, szResponseData, szErrMsg);
		break;
		case CMD_MOND_SET_MODDE:
			ret = do_set_opmode(new_sockfd, &rot_cmd, szResponseData, szErrMsg);
                break;
		case CMD_MOND_GET_TARCONTAINERLIST:
			ret = do_get_tarcontainerlist(new_sockfd, &rot_cmd, szResponseData, szErrMsg);
                break;
		case CMD_MOND_SET_TARCONTAINERLIST:
			ret = do_set_tarcontainerlist(new_sockfd, &rot_cmd, szResponseData, szErrMsg);
                break;
		case CMD_MOND_GET_TARDAEMONLIST:
			ret = do_get_tarDaemonlist(new_sockfd, &rot_cmd, szResponseData, szErrMsg);
                break;
		case CMD_MOND_SET_TARDAEMONLIST:
			ret = do_set_tarDaemonlist(new_sockfd, &rot_cmd, szResponseData, szErrMsg);
                break;
		case CMD_MOND_GET_CPUINFO:
			ret = do_get_cpuinfo(new_sockfd, &rot_cmd, szResponseData, szErrMsg);
                break;
		case CMD_MOND_GET_MEMINFO:
			ret = do_get_meminfo(new_sockfd, &rot_cmd, szResponseData, szErrMsg);	
                break;
		case CMD_MOND_GET_DISKIOINFO:
			ret = do_get_diskIOinfo(new_sockfd, &rot_cmd, szResponseData, szErrMsg);
                break;
		default:
		break;
		}

		
	}
	while(0);

	if (szSendData != NULL && strlen (szSendData) > 0 && szSendData[0] != '\0')
	{
		if (send(new_sockfd->iSocket, szSendData, strlen(szSendData) + 1, 0) == -1)
        	{
            		do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "fail to send message...[%d]", errno);
        	}
        	else
        	{
            		do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "success to send message...(%s)",szSendData);
        	}
	}

	return ret;
}
#endif

/*
 *
 */
int read_data_org(LPSOCKETINFO new_sockfd, ROT_CMD *rot_cmd)
{
    int nread = 0;
    char szBuf[MAX_BUF_SIZE] = {0};
    while (1)
    {
        nread = recv(new_sockfd->iSocket, szBuf, sizeof(szBuf), 0);
        if (nread < 0)
        {
            do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "fail to rot_read....");
            return 0;
        }

	if (strlen(szBuf) > 0)
        {
            //do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "RECV :[%s]", szBuf);

            json_object *recvJson;
            recvJson = json_tokener_parse(szBuf);

            json_object *jsTargetObject = json_object_object_get(json_object_object_get(recvJson, JSON_SUBOBJNAME_REQ), JSON_SUBOBJNAME_TAR);
            json_object *jsHeaderObject = json_object_object_get(json_object_object_get(recvJson, JSON_SUBOBJNAME_REQ), JSON_SUBOBJNAME_HEADER);
            json_object *jsBodyObject = json_object_object_get(json_object_object_get(recvJson, JSON_SUBOBJNAME_REQ), JSON_SUBOBJNAME_BODY);

            if (jsTargetObject == NULL || jsHeaderObject == NULL || jsBodyObject == NULL)
            {
                return FALSE;
            }

            memset(rot_cmd, 0x00, sizeof(ROT_CMD));
            snprintf(rot_cmd->sCmd, MAX_CMD_LEN, "%s", json_object_get_string(get_cmd_at_jsondata(recvJson)));
            snprintf(rot_cmd->sUrl, MAX_URL_LEN, "%s", json_object_get_string(get_targeturl_at_jsondata(jsTargetObject)));
            snprintf(rot_cmd->sTrid, MAX_TRID_LEN, "%s", json_object_get_string(get_trid_at_jsondata(jsHeaderObject)));
            snprintf(rot_cmd->sFunction, MAX_FUN_LEN, "%s", json_object_get_string(get_function_at_jsondata(jsHeaderObject)));
            rot_cmd->pDataObject = jsBodyObject;

            if (jsHeaderObject != NULL)
            {
                json_object_put(jsHeaderObject);
            }

	    if (jsTargetObject != NULL)
            {
                json_object_put(jsTargetObject);
            }

            return TRUE;
        }

        if (strlen(szBuf) == 0)
        {
            do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "RECV data is NULL");
            return TRUE;
        }

        return 0;
    }
}


int read_data(LPSOCKETINFO new_sockfd, ROT_CMD *rot_cmd)
{
    int nread = 0;
    char szBuf[MAX_BUF_SIZE] = {0};
    while (1)
    {
        nread = recv(new_sockfd->iSocket, szBuf, 4096, 0);
        if (nread < 0)
        {
            do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "fail to rot_read....");
            return 0;
        }

        do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "recv data....[%d][%s]", nread,szBuf);

	    if (strlen(szBuf) > 0)
        {
            json_object *recvJson;
            recvJson = json_tokener_parse(szBuf);

            json_object *jsHeaderObject = json_object_object_get(recvJson, JSON_SUBOBJNAME_HEADER);
            json_object *jsBodyObject   = json_object_object_get(recvJson, JSON_SUBOBJNAME_BODY);

            if (jsHeaderObject == NULL || jsBodyObject == NULL)
            {
                return FALSE;
            }

            memset(rot_cmd, 0x00, sizeof(ROT_CMD));
            snprintf(rot_cmd->sCmd, MAX_CMD_LEN, "%s", json_object_get_string(get_cmd_at_jsondata(recvJson)));
            snprintf(rot_cmd->sTrid, MAX_TRID_LEN, "%s", json_object_get_string(get_trid_at_jsondata(jsHeaderObject)));
            rot_cmd->pDataObject = jsBodyObject;

            if (jsHeaderObject != NULL)
            {
                json_object_put(jsHeaderObject);
            }

            return TRUE;
        }

        if (strlen(szBuf) == 0)
        {
            do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "RECV data is NULL");
            return TRUE;
        }

        return 0;
    }
}
