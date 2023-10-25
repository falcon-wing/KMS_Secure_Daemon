#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include "rot_command.h"
#include "monM_def.h"
#include "rot_pam_conf.h"
#include "mond_conf.h"
#include "daemon_func.h"
#include "rot_utils.h"
#include "rot_sock.h"
#include "mon_cpuinfo.h"
#include "mon_meminfo.h"
#include "mon_diskinfo.h"
#include "mon_mntinfo.h"
#include "mon_partitioninfo.h"
extern char g_szRootPath[MAX_FULLPATH_SIZE + 1];
static const char data[]="";

#define IPF_RULE_DEF_ALLDENY  "INPUT|*|*|tcp|-|*|DROP"

#define db_log(fmt, ...) do_rotlog(ROTD_PRODUCT_NAME, 1, fmt, __FILE__,__LINE__, __VA_ARGS__)
/*
 *
 */
void RunTargetContainer(char * TargetContainerName);

/*
 *
 *
 */
int split(char* input, char delim, char*** parts)
{
    int count = 1;
    char** result;
    char* t = input;
    while(*t != '\0')
    {
        if (*t++ == delim)
        {
            count++;
        }
    }

    result = (char**)malloc(count * sizeof(char*));

    t = input;
    int i = 0;
    result[i] = input;
    while(*t != '\0')
    {
        if (*t == delim)
        {
            *t = '\0';
            result[++i] = ++t;
        }
        else
        {
            t++;
        }
    }
    *parts = result;
    return count;
}

/*
 *
 */
static size_t cb(void *data, size_t size, size_t nmemb, void *clientp)
{
	size_t realsize = size * nmemb;
	struct memory *mem = (struct memory *)clientp;

	char *ptr = realloc(mem->response, mem->size + realsize + 1);
	if(ptr == NULL)
		return 0;  /* out of memory! */

	mem->response = ptr;
	memcpy(&(mem->response[mem->size]), data, realsize);
	mem->size += realsize;
	mem->response[mem->size] = 0;

	return realsize;
}

/*
 *
 */
static size_t read_callback(char *dest, size_t size, size_t nmemb, void *userp)
{
	struct WriteThis *wt = (struct WriteThis *)userp;
	size_t buffer_size = size*nmemb;

	if(wt->sizeleft) {
		/* copy as much as possible from the source to the destination */
		size_t copy_this_much = wt->sizeleft;
		if(copy_this_much > buffer_size)
		copy_this_much = buffer_size;
		memcpy(dest, wt->readptr, copy_this_much);

		wt->readptr += copy_this_much;
		wt->sizeleft -= copy_this_much;
		return copy_this_much; /* we copied this many bytes */
	}

	return 0; /* no more data left to deliver */
}

/*
 *
 */
int deserialization_struct_to_containerJson(char * json, struct ContainerState * StatusST)
{
	int ret = 0;

	json_object *val;
	json_object *recvJson;
	json_object *dval, *subVal, *nameVal, *continerIDVal;
	recvJson = json_tokener_parse(json);

	dval = json_object_object_get(recvJson, DOCK_JWT_KEY_STATE);
	if (dval != NULL )
	{
		json_object * statusVal, *RunningVal, *PausedVal, *RestartingVal, *cNameVal;

                statusVal = json_object_object_get(dval, DOCK_JWT_KEY_STATUS);
                if (statusVal != NULL )
                {
                        sprintf (StatusST->Status, "%s", json_object_get_string(statusVal));
                }

                RunningVal = json_object_object_get(dval, DOCK_JWT_KEY_RUNNING);
                if (RunningVal != NULL )
                {
                        StatusST->Running = json_object_get_boolean(RunningVal);
                }

                PausedVal = json_object_object_get(dval, DOCK_JWT_KEY_PAUSED);
                if (PausedVal != NULL )
                {
                        StatusST->Paused = json_object_get_boolean(PausedVal);
                }

                RestartingVal = json_object_object_get(dval, DOCK_JWT_KEY_RESTARTING);
                if (RestartingVal != NULL )
                {
                        StatusST->Restarting = json_object_get_boolean(RestartingVal);
                }

                cNameVal = json_object_object_get(recvJson, DOCK_JWT_KEY_ID);
                if (cNameVal != NULL )
                {
                        sprintf (StatusST->ContainerID, "%s", json_object_get_string(cNameVal));
                }

                ret = 1;
	}

	return ret;
}

/*
 *
 */
void RunTargetContainer(char * TargetContainerName)
{
        CURL *curl;
        CURLcode res;
        struct WriteThis wt;
        char url[1024] = {0};

        sprintf (url, "http://localhost:2378/containers/%s/start", TargetContainerName);

        wt.readptr = data;
        wt.sizeleft = strlen(data);

        curl = curl_easy_init();
        if(curl) {
                /* First set the URL that is about to receive our POST. */
                curl_easy_setopt(curl, CURLOPT_URL, url);
                curl_easy_setopt(curl, CURLOPT_POST, 1L);
                curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);

                curl_easy_setopt(curl, CURLOPT_READDATA, &wt);
                curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
                curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)wt.sizeleft);

                res = curl_easy_perform(curl);
                /* Check for errors */
                if(res != CURLE_OK)
		{
                        //do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, "curl_easy_perform() failed: %s\n" curl_easy_strerror(res));
		}

                curl_easy_cleanup(curl);
        }
}

/*
 *
 */
int start_container_watchdog()
{
	int ret = 0, i = 0, nTarCnt = 0 ;

	json_object *json; 
	curl_global_init(CURL_GLOBAL_ALL);
	CURL *curl;
	struct memory chunk = {0};
	struct ContainerState * status = NULL;
	char szDConfFilePath[MAX_FULLPATH_SIZE] = {0};
	char url[1024] = {0};
	char szWatchDogOpMode[4] = {0};
	char *strCurrPath = NULL;
	char szErrMsg[1024] = {0};
        strCurrPath = rot_getcwd();
	
	snprintf(szDConfFilePath, MAX_FULLPATH_SIZE, "%s/%s/%s", strCurrPath, ROT_CONF, ROT_DCONFILE);

	sprintf (url, "http://127.0.0.1:2378/containers/big_boss/json");

	char **tarTarName;
        char szLineBuf[1024] = {0};
	status = (struct ContainerState *) malloc (sizeof (struct ContainerState));
	while (1)
	{
		monDLogconf_t conf;
		memset (&conf, 0x00, sizeof (conf ));
		get_monD_conf(&conf, szErrMsg);

		//do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, "get conf resutl ....[%s][%c]",conf.szTargetContainer, conf.cWatchDogEnable);
		if (conf.cWatchDogEnable != 'Y')
		{
			sleep(10);
			continue;
		}
		nTarCnt = split(conf.szTargetContainer, ';', &tarTarName);

		//do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, "WatchDog Op mode = [%c], con list = [%s] cnt = [%d]", conf.cWatchDogEnable,conf.szTargetContainer,nTarCnt);

		for (i = 0 ; i < nTarCnt; i ++ )
		{	
			curl = curl_easy_init();
			if (curl )
			{
				memset (&chunk, 0, sizeof (chunk));
				memset (&url, 0, sizeof(url));

				if (strlen (tarTarName[i]) <= 0  || tarTarName[i][0] == 0x00 )
				{
					sleep(1);
					continue;
				}

				sprintf (url, "http://127.0.0.1:2378/containers/%s/json", tarTarName[i]);

				curl_easy_setopt(curl, CURLOPT_URL, url);
				curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cb);
				curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *) &chunk);
				curl_easy_perform(curl);

				curl_easy_cleanup(curl);
				
				if (chunk.response )
				{
					memset (status, 0, sizeof (status));
					//printf ("rsponse = [%s]\n", chunk.response);
					json = json_object_new_object();
					if (deserialization_struct_to_containerJson(chunk.response, status ) == 1 )
					{
						if (status->Running == true)
						{

						}
						else
						{
							do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__,"We've detected the monitoring target container's termination.Now, we'll restart the monitoring target - [%s].", tarTarName[i]);
							RunTargetContainer(tarTarName[i]);
						}
					}
					else
					{
						do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__,"We've detected the monitoring target container's termination. Now, we'll restart the monitoring target - [%s].", tarTarName[i]);
						//do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO,"[%s] is currently exiting. restart again.", tarTarName[i]);
                                                RunTargetContainer(tarTarName[i]);
					}
				}
				else
				{
				//	printf ("response is null......\n");
				}

				//json_object_put(curl);
			}

			sleep(1);
		}

		free (tarTarName);

		sleep(1);
	}

	curl_global_cleanup();
	do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "WatchDog client fin......");

	return ret;
}

/*
 *
 */
int start_pid_watchdog()
{
	int ret = 0, i = 0, nTarCnt = 0 ;
	pid_t nPid;
	BOOL bret = FALSE;
        json_object *json;
	char szDConfFilePath[MAX_FULLPATH_SIZE] = {0};
	char **tarTarName;
        char szLineBuf[1024] = {0};
	char szErrMsg[1024] = {0};
	char *strCurrPath = NULL;
        strCurrPath = g_szRootPath;//rot_getcwd();
	char szTargetpidFileFullPath[MAX_FULLPATH_SIZE] = {0};
	char szTargetFullPath[MAX_FULLPATH_SIZE] = {0};
	char szTest[MAX_FULLPATH_SIZE] = {0};
	while(1)
	{
		monDLogconf_t conf;
                memset (&conf, 0x00, sizeof (conf ));
                get_monD_conf(&conf, szErrMsg);

		if (conf.cWatchDogEnable != 'Y')
                {
                        sleep(10);
                        continue;
                }
		nTarCnt = split(conf.szTargetDaemon, ';', &tarTarName);

		for (i = 0 ; i < nTarCnt; i ++ )
                {

			char szConfigItem[MAX_FULLPATH_SIZE] = {0};
			char szTarName[256] = {0};
			char szFilePath[MAX_FULLPATH_SIZE] = {0};
			if (tarTarName == NULL || 
				tarTarName[i] == NULL || tarTarName[i][0] == 0X00 || strlen(tarTarName[i]) <= 0 )
			{
				sleep(1);
				continue;

			}
			sprintf (szConfigItem, "%s", tarTarName[i]);

			if (strlen(szConfigItem) <= 0 || szConfigItem[0] == 0x00)
			{
				sleep(1);
				continue;
			}
			char * Data = strtok(szConfigItem, "|");
			sprintf (szTarName, "%s", Data);
			Data = strtok(NULL, "|");
			sprintf (szFilePath, "%s", Data);
			
			snprintf(szTargetpidFileFullPath, MAX_FULLPATH_SIZE, "%s/etc/%s.pid", strCurrPath, szTarName);
			bret = is_file(szTargetpidFileFullPath);
			if (bret == TRUE)
			{
				nPid = get_pid(szTargetpidFileFullPath);
				if (nPid == E_RET)
				{
					sleep(2);
					continue;
				}

				ret = find_process(nPid, szTarName);
				if (ret != TRUE )
				{
					char **new_argv;
					sprintf (szTargetFullPath, "%s/%s", szFilePath, szTarName);
					sprintf (szTest, "%s/test", szFilePath);
					
					do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "We've detected the termination of the monitoring target process (daemon). Now, we'll proceed to restart the surveillance target.- [%s]", szTarName);

					system(szTest);
					char *arg[]= {szTarName, "", NULL};
					if (do_cmd_setV2(szTarName,szTargetFullPath) == TRUE )
					{
						do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "target process(daemon) [%s] has been successfully restarted.", szTarName);

					}
					else
					{
						do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "The target process [%s] restart has failed.", szTarName);
					}
					
				}
				else
				{
					//do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, "target [%s] is alive...", szTarName);
				}
			}
			else
			{
				do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "Cannot find the PID file of the target [%s] for monitoring. (%s)", szTarName);
			}
			sleep(1);
		}
		free (tarTarName);
		sleep(1);

	}	

	do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, "start_pid_watchdog call...");
	return ret;
}

/*
 *
 */
int start_wd_watchdog()
{
	int ret = 0, nPid;
	BOOL bret = FALSE;
	char szErrMsg[1024] = {0};
	char *strCurrPath = NULL;
        strCurrPath = g_szRootPath;
	char szTargetpidFileFullPath[MAX_FULLPATH_SIZE] = {0};
        char szTargetFullPath[MAX_FULLPATH_SIZE] = {0};

	do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "start_wd_watchdog...");
	while(1)
        {
                monDLogconf_t conf;
                memset (&conf, 0x00, sizeof (conf ));
                get_monD_conf(&conf, szErrMsg);

                if (conf.cWatchDogEnable != 'Y')
                {
			do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "start_wd_watchdog . continue");
                        sleep(2);
                        continue;
                }

		snprintf(szTargetpidFileFullPath, MAX_FULLPATH_SIZE, "%s/%s/%s.pid", /*strCurrPath*/ROOT_PATH,ETC_DIR ,WATCHDOG_PROGUCTNAME/*MAINDAEMON_PRODUCTNAME*/);
		snprintf(szTargetFullPath, MAX_FULLPATH_SIZE, "%s/%s", ROOT_PATH,  WATCHDOG_PROGUCTNAME/*MAINDAEMON_PRODUCTNAME*/); 


		bret = is_file(szTargetpidFileFullPath);
		if (bret == TRUE )
		{
			nPid = get_pid(szTargetpidFileFullPath);
                        if (nPid == E_RET)
                        {
				do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "start_wd_watchdog::get_pid fail...");
                        	sleep(2);
                                continue;
                        }

                        ret = find_process(nPid, WATCHDOG_PROGUCTNAME/*MAINDAEMON_PRODUCTNAME*/);
                        if (ret != TRUE )
                        {
				if (do_cmd_setV2(WATCHDOG_PROGUCTNAME/*MAINDAEMON_PRODUCTNAME*/,szTargetFullPath) == TRUE )
                                {
                                	do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "target process(daemon) [%s] has been successfully restarted.", WATCHDOG_PROGUCTNAME);
                                }
                                else
                                {
                                	do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "The target process [%s] restart has failed.", WATCHDOG_PROGUCTNAME);
                                }
			}
		}
		else
		{
			sleep(0);
			if (do_cmd_setV2(WATCHDOG_PROGUCTNAME,szTargetFullPath) == TRUE )
			{
				do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "target process(daemon) [%s] has been successfully restarted.", WATCHDOG_PROGUCTNAME);
			}
			else
			{
				do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "The target process [%s] restart has failed.", WATCHDOG_PROGUCTNAME);
			}

		}

		sleep(1);
	}
	
	do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "start_wd_watchdog thread fin...");

	return ret;
}

///< PMA RULE>

char *rot_getrule_at_rulefile(char *_sString, int _nCnt, FILE *fp)
{
    while (fgets(_sString, _nCnt, fp))
    {
        rot_str_removetail_crlf(_sString);
        rot_str_trimwhitespace(_sString, _sString);

        if ( _sString[0] == '\0' || _sString[0] == '#')
        {
            continue;
        }

        return _sString;
    }
    return NULL;
}

char *rot_pam_getrule_at_rulefile(char *_sString, int _nCnt, FILE *fp)
{
    while (fgets(_sString, _nCnt, fp))
    {
        rot_str_removetail_crlf(_sString);
        rot_str_trimwhitespace(_sString, _sString);

        if ( _sString[0] == '\0' || _sString[0] == '#')
        {
            continue;
        }

        return _sString;
    }
    return NULL;
}

static size_t deleteLine( char* buffer, size_t size, const char* playerName )
{
	char* p = buffer;
	bool done = false;
	size_t len = strlen(playerName);
	size_t newSize = 0;
	do
	{
		char *q = strchr(p, *playerName); // look for first letter in playerName
		if (q != NULL)
		{
			if (strncmp(q, playerName, len) == 0) // found name?
			{
				size_t lineSize = 1; // include \n already in line size
				char *line;
				// count number of characters the line has.
				for (line = q; *line != '\n'; ++line)
				{
					++lineSize;
				}

				// calculate length left after line by subtracting offsets
				size_t restSize = (size_t)((buffer + size) - (q + lineSize));

				// move block with next line forward
				memmove(q, q + lineSize, restSize);

				// calculate new size
				newSize = size - lineSize;
				done = true;
			}
			else
			{
				p = q + 1; // continue search
			}
		}
		else
		{
			puts("no such name");
			done = true;
		}
	} while (!done);

	return newSize;
}

int get_pam_op_mode(int *iMode)
{
    int ret = 0;

    return get_rot_pam_op_mode_v2(iMode);
}

int do_get_pam_opmode(LPSOCKETINFO new_sockfd, struct _ROT_CMD *rot_cmd, char * szresponsedata, char * szErrMsg)
{
	int ret = 0, nPamOpMode = 0;
	do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "test...02");
	char *sRetBuf;
	char sData[MAX_BUF_SIZE] = {0};
	char szOpMode[8] = {0};
	
	ret = rotdconf_read_conf("/etc/security/rotPam.conf");
	if (ret == FALSE )
	{
		ret = 0;
	}else
	{
		ret = rotdconf_get_conf("ROT_PAM_OP_MODE", szOpMode);
		rotdconf_close_conf();
		if (strcmp(szOpMode, "ON") == 0)			{
			ret = 1;      
		}
		else if (strcmp(szOpMode, "OFF") == 0)		{
			ret = 0;
		}
		else		{
			ret = 1;
		}
	}

	sRetBuf = make_response_json_v2(rot_cmd->sCmd, "000000", rot_cmd->sTrid, "success", "data", "null", PSRS_TYPE_KEY_ALLINONE);
	sprintf (szresponsedata, "%s", sRetBuf);

	return ret;
}

int do_appand_ipf_rule(LPSOCKETINFO new_socefd, struct _ROT_CMD *rot_cmd, char * szresponsedata, int moredata,char *szErrMsg)
{
	int ret = 0, iMode = 0, index = -1;
	char *sRetBuf;
	char sData[MAX_BUF_SIZE] = {0};
	char szAppandTarRule[1024] = {0};
	char szRotateEnable[MAX_FULLPATH_SIZE] = {0};
	snprintf (szAppandTarRule, MAX_FULLPATH_SIZE, "%s", json_object_get_string(   json_object_object_get( rot_cmd->pDataObject, "ipf_tar_rule")));

	do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "szAppandTarRule = {%s}",szAppandTarRule);
	bool bRet = chk_fw_org_rule(szAppandTarRule, &index);
	if (bRet == false)
	{
		oper_fw_rule(0, szAppandTarRule, szErrMsg);
	}
	else
	{
		do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "already exist...");
	}

	sRetBuf = make_response_json_v2(rot_cmd->sCmd, "000000", rot_cmd->sTrid, "success", "data", "null", PSRS_TYPE_KEY_ALLINONE);
	sprintf (szresponsedata, "%s", sRetBuf);
	return TRUE;

}

int do_delete_ipf_rule(LPSOCKETINFO new_socefd, struct _ROT_CMD *rot_cmd, char * szresponsedata, int* moredata,char *szErrMsg)
{
	int ret = 0, iMode = 0, index = -1, nMore = 0;
	char *sRetBuf;
	char sData[MAX_BUF_SIZE] = {0};
	char szDeletePath[1024] = {0};
	char szDeleteTarRule[1024] = {0};
	char szRotateEnable[MAX_FULLPATH_SIZE] = {0};
	snprintf (szDeleteTarRule, MAX_FULLPATH_SIZE, "%s", json_object_get_string(   json_object_object_get( rot_cmd->pDataObject, "ipf_tar_rule")));
	nMore = atoi(json_object_get_string(   json_object_object_get( rot_cmd->pDataObject, "more_data")));
	do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "szAppandTarRule = {%s}",szDeleteTarRule);
	bool bRet = chk_fw_org_rule(szDeleteTarRule, &index);
	if (bRet == true)
	{
		sprintf (szDeletePath, "/sbin/iptables -D INPUT %d", index);
		system (szDeletePath );
	}
	else
	{
		do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "already exist...");
	}

	sRetBuf = make_response_json_v2(rot_cmd->sCmd, "000000", rot_cmd->sTrid, "success", "data", "null", PSRS_TYPE_KEY_ALLINONE);
	sprintf (szresponsedata, "%s", sRetBuf);
	*moredata = nMore;
	return TRUE;

}

int do_insert_ipf_rule(LPSOCKETINFO new_socefd, struct _ROT_CMD *rot_cmd, char * szresponsedata, int* moredata,char *szErrMsg)
{
	int ret = 0, iMode = 0, index = -1, nMore = 0;
	char *sRetBuf;
	char sData[MAX_BUF_SIZE] = {0};
	char szAppandTarRule[1024] = {0};
	char szRotateEnable[MAX_FULLPATH_SIZE] = {0};
	snprintf (szAppandTarRule, MAX_FULLPATH_SIZE, "%s", json_object_get_string(   json_object_object_get( rot_cmd->pDataObject, "ipf_tar_rule")));
	nMore = atoi(json_object_get_string(   json_object_object_get( rot_cmd->pDataObject, "more_data")));
	bool bRet = chk_fw_org_rule(szAppandTarRule, &index);
	if (bRet == false)
	{
		oper_fw_rule(2, szAppandTarRule, szErrMsg);
		sprintf (sData, "Result|success;");
	}
	else
	{
		do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "already exist...");
		sprintf (sData, "Result|fail;");
	}

	char szAllDenyRule[1024] = {0};
	sprintf (szAllDenyRule, "%s", IPF_RULE_DEF_ALLDENY);
	bRet = chk_fw_org_rule(szAllDenyRule, &index);
	if (bRet == false)
	{
		
		oper_fw_rule(0, szAllDenyRule, szErrMsg);
	}

	sRetBuf = make_response_json_v2(rot_cmd->sCmd, "000000", rot_cmd->sTrid, "success", "data", "null", PSRS_TYPE_KEY_ALLINONE);
	sprintf (szresponsedata, "%s", sRetBuf);
	*moredata = nMore;
	return TRUE;
}

int do_insert_ipf_rule_without_default(LPSOCKETINFO new_socefd, struct _ROT_CMD *rot_cmd, char * szresponsedata, int* moredata,char *szErrMsg)
{
	int ret = 0, iMode = 0, index = -1, nMore = 0;
	char *sRetBuf;
	char sData[MAX_BUF_SIZE] = {0};
	char szMoreData[4] = {0};
	char szAppandTarRule[MAX_BUF_SIZE] = {0};
	char szRotateEnable[MAX_FULLPATH_SIZE] = {0};
	bool bRet = false;
	sprintf (szAppandTarRule, "%s", json_object_get_string(   json_object_object_get( rot_cmd->pDataObject, "ipf_tar_rule")));
	sprintf (szMoreData, "%s", json_object_get_string(   json_object_object_get( rot_cmd->pDataObject, "more_data")));
	nMore = atoi(szMoreData);
	if (strchr(szAppandTarRule, ';') != NULL)
	{
		char **tarTarName;
		int i = 0;

		char *token, *str, *tofree;
		char szTmpBak[MAX_BUF_SIZE];
		sprintf (szTmpBak, "%s", szAppandTarRule);
		tofree = str = strdup(szTmpBak);  // We own str's memory now.
		while ((token = strsep(&str, ";"))) 
		{
			//do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "test --004-1(%s)",token);
			bRet = chk_fw_org_rule(token, &index);
			if (bRet == false)
			{
				oper_fw_rule(2, token, szErrMsg);
			}
		}
		free(tofree);
/*
		int nCnt = split(szAppandTarRule, ';', &tarTarName);
		for (i = 0 ; i < nCnt ; i ++ )
		{
			char szTmp[1024];
			if (tarTarName[i] == NULL || strlen(tarTarName[i]) <= 0)
			{
				continue;
			}

			strncpy(szTmp, tarTarName[i], strlen (tarTarName[i]));
			do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "test --004-1(%s)",szTmp);

			
			bRet = chk_fw_org_rule(szTmp, &index);
			
			if (bRet == false)
			{
				oper_fw_rule(2, szTmp, szErrMsg);
			}
			do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "test --005-3");
			
		}
		*/
	}
	else
	{
		bRet = chk_fw_org_rule(szAppandTarRule, &index);
		if (bRet == false)
		{
			oper_fw_rule(2, szAppandTarRule, szErrMsg);
		}
		else
		{
			do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "already exist...");
		}
	}

	sRetBuf = make_response_json_v2(rot_cmd->sCmd, "000000", rot_cmd->sTrid, "success", "data", "null", PSRS_TYPE_KEY_ALLINONE);
	sprintf (szresponsedata, "%s", sRetBuf);

	*moredata = nMore;
	return TRUE;
}

int do_set_ipf_rule(LPSOCKETINFO new_sockfd, struct _ROT_CMD *rot_cmd,char * szresponsedata, char * szErrMg)
{
	int ret, lineno, o_mask, index = -1;
	int nCnt = 0, i;
	FILE* pFile;
	char *szData[32];
	char *sRetBuf;
	char szLineBuf[MAX_LOG_BUF] = {0};
	char sData[1024] = {0};
	char szRulePath[MAXPATHLEN + 1] = {0};
	char szRuleOrgPath[MAXPATHLEN + 1] = {0};
	char szRuleTmpPath[ MAXPATHLEN + 1] = {0};
	char szRuleBackPath[ MAXPATHLEN + 1] = {0};
	
	snprintf (sData, MAX_BUF_SIZE, "%s", json_object_get_string(   json_object_object_get( rot_cmd->pDataObject, "ipf_tar_rule")));

	if (sData == NULL || strlen (sData ) <= 0 )
	{
		szErrMg = "There is no request data";
		sRetBuf = make_response_json_v2(rot_cmd->sCmd, "000001", rot_cmd->sTrid, "An error occurred during processing", "error_msg", szErrMg, PARS_TYPE_ALLINONE);
		sprintf (szresponsedata, "%s", sRetBuf);
		return false;
	}

	//nCnt = rot_str_xparsestring(sData,'|', szData, 32);
	char **tarTarName;
	nCnt = split(sData, ';', &tarTarName);
	//nCnt = pars_data_objs(sData, szData);
	for (i = 0 ; i < nCnt ; i ++ )
	{
		char szTmp[1024];
		if (tarTarName[i] == NULL || strlen(tarTarName[i]) <= 0)
		{
			continue;
		}

		//sprintf (szTmp, "%s", szData[i] );
		strcpy(szTmp, tarTarName[i]);

		bool bRet = chk_fw_org_rule(szTmp, &index);
		if (bRet == false)
		{
			oper_fw_rule(2, szTmp, szErrMg);
		}
		else
		{
		}
	}

	if(pFile)
		fclose(pFile);

	sRetBuf = make_response_json_v2(rot_cmd->sCmd, "000000", rot_cmd->sTrid, "success","data", "null", PSRS_TYPE_KEY_ALLINONE);
	sprintf (szresponsedata, "%s", sRetBuf);

	return 1;
}

//CMD_PAM_SET_OP_MODE
int do_set_pam_opmode(LPSOCKETINFO new_socefd, struct _ROT_CMD *rot_cmd, char * szresponsedata, char *szErrMsg)
{
	int ret = 0, iMode = 0, index = -1;
	rotDconf_t rotConf;
	char *sRetBuf;
	char sData[MAX_BUF_SIZE] = {0};
	char szIMode[4] = {0};
	char szRotateEnable[MAX_FULLPATH_SIZE] = {0};
	memset (&rotConf, 0x00, sizeof (rotConf));

	//iMode = atoi(json_object_get_string(   json_object_object_get( rot_cmd->pDataObject, ROT_PAM_OP_MODE)));
	snprintf (szIMode, MAX_FULLPATH_SIZE, "%s", json_object_get_string(   json_object_object_get( rot_cmd->pDataObject, "pam_op_mode")));

	if (strcmp (szIMode, "ON") == 0 )
	{
			iMode = 1;
	}
	else
	{
			iMode = 0;
	}

	if (set_rot_pam_op_mode( iMode, szErrMsg) != TRUE )
	{
			do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, "fail to set rotdaemon configuration..(%d)(%s)", errno,szErrMsg);
			json_object_put(rot_cmd->pDataObject);
			return ret;
	}

	json_object_put(rot_cmd->pDataObject);

	sprintf (sData, "pam_op_mode|%s;",szIMode);

	sRetBuf = make_response_json_v2(rot_cmd->sCmd, "000000", rot_cmd->sTrid, "success", NULL, sData, 0);
	sprintf (szresponsedata, "%s", sRetBuf);

	return TRUE;
}

//CMD_PAM_GET_RULE
int do_get_pam_rule(LPSOCKETINFO new_sockfd, struct _ROT_CMD *rot_cmd, char * szresponsedata, char * szErrMsg)
{
        int ret = 0, nTotalSize =0 , nBufSize = 0;
        char *sRetBuf;
        char szDConfDir[MAX_FULLPATH_SIZE] = {0};
        char szLineBuf[MAX_LOG_BUF] = {0};
        char sData[MAX_BUF_SIZE] = {0};
        char szRulePath[MAXPATHLEN + 1] = {0};
        char szTmpBuf[MAX_LOG_BUF] = {0};

        memset (&sData, 0x00 , sizeof (sData));
        sprintf (szRulePath, "%s%s", PAM_ACL_RULE_DIR, "rotPam.rule");

        FILE * Rfp = NULL;
        int nRuleCnt = 0;
        Rfp = rot_file_fopen(szRulePath, "r");
        while (rot_getrule_at_rulefile(szLineBuf, sizeof (szLineBuf), Rfp ))
        {
			memset (&szTmpBuf, 0x00 , sizeof (szTmpBuf));
			sprintf (szTmpBuf, "%s;", szLineBuf);

			nBufSize = strlen(szTmpBuf);
			nTotalSize = nBufSize + strlen (sData);

			if (nTotalSize > MAX_BUF_SIZE)
			{
				do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, "pam rule data is overflow...");
				break;
			}

			strcat(sData,szTmpBuf);

			nRuleCnt ++;
        }

        sRetBuf = make_response_json_v2(rot_cmd->sCmd, "000000", rot_cmd->sTrid, "success", "pam_rule_data",sData, PARS_TYPE_ALLINONE);
        sprintf (szresponsedata, "%s", sRetBuf);

		fclose(Rfp);
        return TRUE;
}

int do_get_pam_ruleV2(LPSOCKETINFO new_sockfd, struct _ROT_CMD *rot_cmd, char * szresponsedata, char * szErrMsg)
{
        int ret = 0, nTotalSize =0 , nBufSize = 0;
        char *sRetBuf;
        char szDConfDir[MAX_FULLPATH_SIZE] = {0};
        char szLineBuf[MAX_LOG_BUF] = {0};
        char sData[MAX_BUF_SIZE] = {0};
        char szRulePath[MAXPATHLEN + 1] = {0};
        char szTmpBuf[MAX_LOG_BUF] = {0};
        char szRuleType[128] = {0};
        memset (&sData, 0x00 , sizeof (sData));
        sprintf (szRuleType, "%s", json_object_get_string(   json_object_object_get( rot_cmd->pDataObject, "pam_rule_type")));

        if ( strcmp (szRuleType, "USER") == 0 )
        {
                sprintf (szRulePath, "%s%s", PAM_ACL_RULE_DIR, PAM_ACL_USERRULE_FILE);
        }
        else if (strcmp (szRuleType, "GROUP") == 0 )
        {
                sprintf (szRulePath, "%s%s", PAM_ACL_RULE_DIR, PAM_ACL_GROUPRULE_FILE);
        }
        else if (strcmp (szRuleType, "DEFAULT") == 0 )
        {
                sprintf (szRulePath, "%s%s", PAM_ACL_RULE_DIR, PAM_ACL_DEFAULTRULE_FILE);
        }
        else
        {
                sprintf (szRulePath, "%s%s", PAM_ACL_RULE_DIR, PAM_ACL_USERRULE_FILE);
        }

        FILE * Rfp = NULL;
        int nRuleCnt = 0;
        Rfp = rot_file_fopen(szRulePath, "r");
        while (rot_getrule_at_rulefile(szLineBuf, sizeof (szLineBuf), Rfp ))
        {
                memset (&szTmpBuf, 0x00 , sizeof (szTmpBuf));
                sprintf (szTmpBuf, "%s;", szLineBuf);

                nBufSize = strlen(szTmpBuf);
                nTotalSize = nBufSize + strlen (sData);

                if (nTotalSize > MAX_BUF_SIZE)
                {
                    break;
                }

                strcat(sData,szTmpBuf);
				nRuleCnt ++;
        }

        sRetBuf = make_response_json_v2(rot_cmd->sCmd, "000000", rot_cmd->sTrid, "success", "pam_rule_data", sData, PARS_TYPE_ALLINONE);
        sprintf (szresponsedata, "%s", sRetBuf);

        fclose(Rfp);
        return TRUE;
}

int do_add_pam_rule(LPSOCKETINFO new_sockfd, struct _ROT_CMD *rot_cmd, char * szresponsedata, int *moredata, char * szErrMg)
{
	int ret = 0, nTotalSize =0 , nBufSize = 0, nMore;
	char *sRetBuf;
	char szDConfDir[MAX_FULLPATH_SIZE] = {0};
	char szLineBuf[MAX_LOG_BUF] = {0};
	char sData[MAX_BUF_SIZE] = {0};
	char szRulePath[MAXPATHLEN + 1] = {0};
	char szTmpBuf[MAX_LOG_BUF] = {0};
	char szRuleType[128] = {0};
	char szErrItem[4096] = {0};
	memset (&sData, 0x00 , sizeof (sData));

	sprintf (szRuleType, "%s", json_object_get_string(   json_object_object_get( rot_cmd->pDataObject, "pam_rule_type")));
	nMore = atoi(json_object_get_string(   json_object_object_get( rot_cmd->pDataObject, "more_data")));
	sprintf (sData,  "%s", json_object_get_string(   json_object_object_get( rot_cmd->pDataObject, "pam_rule_data")));
	if (sData == NULL || strlen (sData ) <= 0 )
	{
		szErrMg = "There is no request data";
		sRetBuf = make_response_json_v2(rot_cmd->sCmd, "000001", rot_cmd->sTrid, "An error occurred during processing", "error_msg", szErrMg, PARS_TYPE_ALLINONE);
		sprintf (szresponsedata, "%s", sRetBuf);
		return false;
	}


	if ( strcmp (szRuleType, "USER") == 0 )
	{
			sprintf (szRulePath, "%s%s", PAM_ACL_RULE_DIR, PAM_ACL_USERRULE_FILE);
	}
	else if (strcmp (szRuleType, "GROUP") == 0 )
	{
			sprintf (szRulePath, "%s%s", PAM_ACL_RULE_DIR, PAM_ACL_GROUPRULE_FILE);
	}
	else if (strcmp (szRuleType, "DEFAULT") == 0 )
	{
			sprintf (szRulePath, "%s%s", PAM_ACL_RULE_DIR, PAM_ACL_DEFAULTRULE_FILE);
	}
	else
	{
			sprintf (szRulePath, "%s%s", PAM_ACL_RULE_DIR, PAM_ACL_USERRULE_FILE);
	}


	FILE * Rfp = NULL;
	int nRuleCnt = 0;
	bool bFindTarget = false;

	if (strchr(sData, ';') != NULL)
	{
		char **tarTarName;
		int i = 0;
		char szTmpData[4096] = {0};
		
		sprintf (szTmpBuf, "%s", sData);
		int nCnt = split(szTmpBuf, ';', &tarTarName);
		for (i = 0 ; i < nCnt ; i ++ )
		{
			Rfp = rot_file_fopen(szRulePath, "r");
			while (rot_getrule_at_rulefile(szLineBuf, sizeof (szLineBuf), Rfp ))
			{
				if (strcmp (szLineBuf, tarTarName[i]) == 0 )
				{
					bFindTarget = true;
					break;
				}
				nRuleCnt ++;
			}

			if (Rfp != NULL)
			{
				fclose(Rfp);
			}
			if (bFindTarget != true)
			{
				Rfp = rot_file_fopen(szRulePath, "a");
				if (bFindTarget != true)
				{
					fputs(tarTarName[i], Rfp);
					fputs("\n", Rfp);
				}
				else{
					strcat(szErrItem, tarTarName[i]);
					strcat(szErrItem, ";");
				}

				if (Rfp != NULL)
				{
					fclose(Rfp);
				}
			}
			else{
				
			}
		}
	}
	else
	{
		Rfp = rot_file_fopen(szRulePath, "r");
		while (rot_getrule_at_rulefile(szLineBuf, sizeof (szLineBuf), Rfp ))
		{
				if (strcmp (szLineBuf, sData) == 0 )
				{
					bFindTarget = true;
					break;
				}
				nRuleCnt ++;
		}
		if (Rfp)
			fclose(Rfp);

		if (bFindTarget != true)
		{
			Rfp = rot_file_fopen(szRulePath, "a");
			if (bFindTarget != true)
			{
				fputs(sData, Rfp);
				fputs("\n", Rfp);
			}
			else{
				strcat(szErrItem, sData);
				strcat(szErrItem, ";");
				ret = false;
			}

			//sRetBuf = make_response_json_v2(rot_cmd->sCmd, "000000", rot_cmd->sTrid, "Success", "pam_rule_data", sData, PARS_TYPE_ALLINONE);
			ret = true;
		}
		else{
/*
			sRetBuf = make_response_json_v2(rot_cmd->sCmd, "000001", rot_cmd->sTrid, "An error occurred during processing", "error_msg", "already have the same policy", PARS_TYPE_ALLINONE);
			szErrMg = "An error occurred during processing";
*/
			
		}
	}

	if (strlen (szErrItem) > 0)
	{
		sRetBuf = make_response_json_v2(rot_cmd->sCmd, "000001", rot_cmd->sTrid, "An error occurred during processing", "error_msg", szErrItem, PARS_TYPE_ALLINONE);
		ret = false;
	}
	else
	{
		sRetBuf = make_response_json_v2(rot_cmd->sCmd, "000000", rot_cmd->sTrid, "success", "data", "null", PARS_TYPE_ALLINONE);
		ret = true;
	}
	

	*moredata = nMore;
	sprintf (szresponsedata, "%s", sRetBuf);
	
	return ret;
}

int do_del_pam_rule(LPSOCKETINFO new_sockfd, struct _ROT_CMD *rot_cmd,char * szresponsedata, int *moredata,char * szErrMg)
{
	int ret, lineno, o_mask, nBufSize = 0, nTotalSize = 0, nMore;
	int nCnt = 0, i = 0 ,nRuleCnt = 0;
	bool bFindTarget = false;
	FILE* pFile;
	FILE * Rfp = NULL;
	char *sRetBuf;
	char *szData[32];
	char ** ppTarData;
	char szTarBakBuf[1024] = {0}, szLineBuf[MAX_LOG_BUF] = {0}, sRecvData[MAX_BUF_SIZE] = {0};
	char szRulePath[MAXPATHLEN + 1] = {0}, szRuleOrgPath[MAXPATHLEN + 1] = {0}, szRuleTmpPath[ MAXPATHLEN + 1] = {0}, szRuleBackPath[ MAXPATHLEN + 1] = {0};
	char szTmpBuf[MAX_LOG_BUF] = {0};
	char sData[MAX_BUF_SIZE] = {0};
	char szRuleType[128] = {0};
	
	sprintf (szRuleType, "%s",json_object_get_string(   json_object_object_get( rot_cmd->pDataObject, "pam_rule_type")));
	nMore = atoi(json_object_get_string(   json_object_object_get( rot_cmd->pDataObject, "more_data")));
	snprintf (sRecvData, MAX_BUF_SIZE, "%s", json_object_get_string(   json_object_object_get( rot_cmd->pDataObject, "pam_rule_data")));
	if (sRecvData == NULL || strlen (sRecvData ) <= 0 )
	{
		szErrMg = "There is no request data";
		sRetBuf = make_response_json_v2(rot_cmd->sCmd, "000001", rot_cmd->sTrid, "An error occurred during processing", "error_msg", szErrMg, PARS_TYPE_ALLINONE);
		sprintf (szresponsedata, "%s", sRetBuf);
		return false;
	}

	if ( strcmp (szRuleType, "USER") == 0 )
	{
			sprintf (szRulePath, "%s%s", PAM_ACL_RULE_DIR, PAM_ACL_USERRULE_FILE);
	}
	else if (strcmp (szRuleType, "GROUP") == 0 )
	{
			sprintf (szRulePath, "%s%s", PAM_ACL_RULE_DIR, PAM_ACL_GROUPRULE_FILE);
	}
	else if (strcmp (szRuleType, "DEFAULT") == 0 )
	{
			sprintf (szRulePath, "%s%s", PAM_ACL_RULE_DIR, PAM_ACL_DEFAULTRULE_FILE);
	}
	else
	{
			sprintf (szRulePath, "%s%s", PAM_ACL_RULE_DIR, PAM_ACL_USERRULE_FILE);
	}

	Rfp = rot_file_fopen(szRulePath, "r");
	while (rot_getrule_at_rulefile(szLineBuf, sizeof (szLineBuf), Rfp ))
	{
			memset (&szTmpBuf, 0x00 , sizeof (szTmpBuf));
			sprintf (szTmpBuf, "%s", szLineBuf);
			nBufSize = strlen(szTmpBuf);
			if (strcmp (szTmpBuf, sRecvData) == 0 )
			{
				continue;
			}

			else 
			{
				strcat(sData,szTmpBuf);
				strcat(sData,"\n");
			}
	}

	fclose(Rfp);

	Rfp = rot_file_fopen(szRulePath, "w");
	if (bFindTarget != true)
	{
		fputs(sData, Rfp);
	}
	else{

		szErrMg = "An error occurred during processing";
		sRetBuf = make_response_json_v2(rot_cmd->sCmd, "000001", rot_cmd->sTrid, szErrMg, "error_msg", "There is no policy file", PARS_TYPE_ALLINONE);
		
		return false;
	}

	*moredata = nMore;
	sRetBuf = make_response_json_v2(rot_cmd->sCmd, "000000", rot_cmd->sTrid, "success", "pam_rule_data", sData, PARS_TYPE_ALLINONE);
	sprintf (szresponsedata, "%s", sRetBuf);

	return 1;
}

int do_del_pam_rule_org(LPSOCKETINFO new_sockfd, struct _ROT_CMD *rot_cmd,char * szresponsedata,int* moredata, char * szErrMg)
{
	int ret, lineno, o_mask,nMore;
	int nCnt = 0, i;
	FILE* pFile;
	char *sRetBuf;
	char *szData[32];
	char ** ppTarData;
	char szTarBakBuf[1024] = {0};
	char szLineBuf[MAX_LOG_BUF] = {0};
	char sData[MAX_BUF_SIZE] = {0};
	char szRulePath[MAXPATHLEN + 1] = {0};
	char szRuleOrgPath[MAXPATHLEN + 1] = {0};
	char szRuleTmpPath[ MAXPATHLEN + 1] = {0};
	char szRuleBackPath[ MAXPATHLEN + 1] = {0};
	char szRuleType[128] = {0};
	//char szRuleOption[128] = {0};
	sprintf (szRuleType, "%s",json_object_get_string(   json_object_object_get( rot_cmd->pDataObject, "pam_rule_type")));
	nMore = atoi(json_object_get_string(   json_object_object_get( rot_cmd->pDataObject, "more_data")));
	snprintf (sData, MAX_BUF_SIZE, "%s", json_object_get_string(   json_object_object_get( rot_cmd->pDataObject, "pam_rule_data")));
	if (sData == NULL || strlen (sData ) <= 0 )
	{
		szErrMg = "There is no request data";
		sRetBuf = make_response_json_v2(rot_cmd->sCmd, "000001", rot_cmd->sTrid, "An error occurred during processing", "error_msg", szErrMg, PARS_TYPE_ALLINONE);
		sprintf (szresponsedata, "%s", sRetBuf);
		return false;
	}

	if ( strcmp (szRuleType, "USER") == 0 )
	{
			sprintf (szRuleOrgPath, "%s%s", PAM_ACL_RULE_DIR, PAM_ACL_USERRULE_FILE);
			sprintf (szRuleTmpPath, "%s%s_tmp", PAM_ACL_RULE_DIR, PAM_ACL_USERRULE_FILE);
	}
	else if (strcmp (szRuleType, "GROUP") == 0 )
	{
			sprintf (szRuleOrgPath, "%s%s", PAM_ACL_RULE_DIR, PAM_ACL_GROUPRULE_FILE);
			sprintf (szRuleTmpPath, "%s%s_tmp", PAM_ACL_RULE_DIR, PAM_ACL_GROUPRULE_FILE);
	}
	else if (strcmp (szRuleType, "DEFAULT") == 0 )
	{
			sprintf (szRuleOrgPath, "%s%s", PAM_ACL_RULE_DIR, PAM_ACL_DEFAULTRULE_FILE);
			sprintf (szRuleTmpPath, "%s%s_tmp", PAM_ACL_RULE_DIR, PAM_ACL_DEFAULTRULE_FILE);
	}
	else
	{
			sprintf (szRuleOrgPath, "%s%s", PAM_ACL_RULE_DIR, PAM_ACL_USERRULE_FILE);
			sprintf (szRuleTmpPath, "%s%s_tmp", PAM_ACL_RULE_DIR, PAM_ACL_USERRULE_FILE);
	}

	struct stat st;
	if ( stat( szRuleOrgPath, &st ) != -1 )
    {
		FILE* fp = fopen( szRuleOrgPath, "rb" );
      	if ( fp != NULL )
      	{
			char* buffer = malloc( st.st_size ); 
			if ( fread(buffer, 1, st.st_size, fp) == st.st_size)
			{
				fclose(fp);

				size_t newSize = deleteLine( buffer, st.st_size, sData );

				fp = fopen( szRuleOrgPath, "wb" );
				if ( fp != NULL )
				{
					fwrite(buffer, 1, newSize, fp);
					fclose(fp);
				}
				else
				{
					perror(szRuleOrgPath);
				}
			}
        free(buffer);
      }
      else
      {
		szErrMg = "An error occurred during processing";
		sRetBuf = make_response_json_v2(rot_cmd->sCmd, "000001", rot_cmd->sTrid, szErrMg, "error_msg", "There is no policy file", PARS_TYPE_ALLINONE);
		
		return false;
        
      }
	}
	else
	{
		szErrMg = "An error occurred during processing";
		sRetBuf = make_response_json_v2(rot_cmd->sCmd, "000001", rot_cmd->sTrid, szErrMg, "error_msg", "There is no policy file", PARS_TYPE_ALLINONE);
		
		return false;
	}

	sRetBuf = make_response_json_v2(rot_cmd->sCmd, "000000", rot_cmd->sTrid, "success", "pam_rule_data", sData, PARS_TYPE_ALLINONE);
	sprintf (szresponsedata, "%s", sRetBuf);
	*moredata = nMore;
	return true;
}
//CMD_PAM_SET_RULE
int do_set_pam_rule(LPSOCKETINFO new_sockfd, struct _ROT_CMD *rot_cmd,char * szresponsedata, char * szErrMg)
{
	int ret, lineno, o_mask;
	int nCnt = 0, i;
	FILE* pFile;
	char *szData[32];
	char *sRetBuf;
	char szLineBuf[MAX_LOG_BUF] = {0};
	char sData[MAX_BUF_SIZE] = {0};
	char szRulePath[MAXPATHLEN + 1] = {0};
	char szRuleOrgPath[MAXPATHLEN + 1] = {0};
	char szRuleTmpPath[ MAXPATHLEN + 1] = {0};
	char szRuleBackPath[ MAXPATHLEN + 1] = {0};
	char szRuleType[128] = {0};
	sprintf (szRuleType, "%s",json_object_get_string(   json_object_object_get( rot_cmd->pDataObject, "pam_rule_type")));
	
	snprintf (sData, MAX_BUF_SIZE, "%s", json_object_get_string(   json_object_object_get( rot_cmd->pDataObject, "pam_rule_data")));

	if (sData == NULL || strlen (sData ) <= 0 )
	{
		szErrMg = "There is no request data";
		sRetBuf = make_response_json_v2(rot_cmd->sCmd, "000001", rot_cmd->sTrid, "An error occurred during processing", "error_msg", szErrMg, PARS_TYPE_ALLINONE);
		sprintf (szresponsedata, "%s", sRetBuf);
		return false;
	}

	if ( strcmp (szRuleType, "USER") == 0 )
	{
			sprintf (szRuleOrgPath, "%s%s", PAM_ACL_RULE_DIR, PAM_ACL_USERRULE_FILE);
			sprintf (szRuleTmpPath, "%s%s_tmp", PAM_ACL_RULE_DIR, PAM_ACL_USERRULE_FILE);
			sprintf (szRuleBackPath, "%s%s_bak", PAM_ACL_RULE_DIR, PAM_ACL_USERRULE_FILE);
	}
	else if (strcmp (szRuleType, "GROUP") == 0 )
	{
			sprintf (szRuleOrgPath, "%s%s", PAM_ACL_RULE_DIR, PAM_ACL_GROUPRULE_FILE);
			sprintf (szRuleTmpPath, "%s%s_tmp", PAM_ACL_RULE_DIR, PAM_ACL_GROUPRULE_FILE);
			sprintf (szRuleBackPath, "%s%s_bak", PAM_ACL_RULE_DIR, PAM_ACL_GROUPRULE_FILE);
	}
	else if (strcmp (szRuleType, "DEFAULT") == 0 )
	{
			sprintf (szRuleOrgPath, "%s%s", PAM_ACL_RULE_DIR, PAM_ACL_DEFAULTRULE_FILE);
			sprintf (szRuleTmpPath, "%s%s_tmp", PAM_ACL_RULE_DIR, PAM_ACL_DEFAULTRULE_FILE);
			sprintf (szRuleBackPath, "%s%s_bak", PAM_ACL_RULE_DIR, PAM_ACL_DEFAULTRULE_FILE);
	}
	else
	{
			sprintf (szRuleOrgPath, "%s%s", PAM_ACL_RULE_DIR, PAM_ACL_USERRULE_FILE);
			sprintf (szRuleTmpPath, "%s%s_tmp", PAM_ACL_RULE_DIR, PAM_ACL_USERRULE_FILE);

			sprintf (szRuleBackPath, "%s%s_bak", PAM_ACL_RULE_DIR, PAM_ACL_USERRULE_FILE);
	}

	o_mask = umask(077);
	pFile = fopen(szRuleTmpPath, "w");
	if (pFile == NULL )
	{
		szErrMg = "An error occurred during processing";
		sRetBuf = make_response_json_v2(rot_cmd->sCmd, "000001", rot_cmd->sTrid, szErrMg, "error_msg", "The file saving has failed.", PARS_TYPE_ALLINONE);
		
		return false;
	}
	umask(o_mask);

	if (rename (szRuleOrgPath, szRuleBackPath) == -1)
	{
		szErrMg = "An error occurred during processing";
		sRetBuf = make_response_json_v2(rot_cmd->sCmd, "000001", rot_cmd->sTrid, szErrMg, "error_msg", "The file saving has failed.", PARS_TYPE_ALLINONE);
		

		return false;
	}

	//nCnt = rot_str_xparsestring(sData,'|', szData, 32);
	char **tarTarName;
	nCnt = split(sData, ';', &tarTarName);
	for (i = 0 ; i < nCnt ; i ++ )
	{
		fputs(tarTarName[i], pFile);
	}

	fclose(pFile);

	//6. rename new rule file name to the old file name
	if (rename (szRuleTmpPath, szRuleOrgPath) == -1 )
	{
		szErrMg = "An error occurred during processing";
		sRetBuf = make_response_json_v2(rot_cmd->sCmd, "000001", rot_cmd->sTrid, szErrMg, "error_msg", "The file saving has failed", PARS_TYPE_ALLINONE);
		
		return false;
	}

	sRetBuf = make_response_json_v2(rot_cmd->sCmd, "000000", rot_cmd->sTrid, "success","data", "null", PSRS_TYPE_KEY_ALLINONE);
	sprintf (szresponsedata, "%s", sRetBuf);

	return 1;
}

/*
 * do_get_monD_mode
 */
int do_get_monD_mode(LPSOCKETINFO new_sockfd, struct _ROT_CMD *rot_cmd, char * szresponsedata,char * szErrMsg)
{
	int ret = 0;
	char * strResultData;
	char sData[MAX_BUF_SIZE] = {0};
	monDLogconf_t conf;
        memset (&conf, 0x00, sizeof (conf ));
        get_monD_conf(&conf, szErrMsg);

	if (conf.cWatchDogEnable == 0x00 )
	{
		return 0;
	}
	
	else
	{
		if (conf.cWatchDogEnable == 'Y')
			sprintf (sData, "watchd_op_mode|ON");
		else 
			sprintf (sData, "watchd_op_mode|OFF"); 
	}

	strResultData = make_response_json_v2(rot_cmd->sCmd, "000000", rot_cmd->sTrid, "success", NULL , sData, 0 );
	sprintf (szresponsedata, "%s", strResultData );

	return 1;
}

/*
 * do_set_monD_mode
 */
int do_set_monD_mode(LPSOCKETINFO new_sockfd, struct _ROT_CMD * rot_cmd, char * szresponsedata, char * szErrMsg)
{
	int ret = 0;

	if (strcmp (json_object_get_string(   json_object_object_get( rot_cmd->pDataObject, "watchd_op_mode")) , MODE_ON) == 0)
	{
		set_conf_type_of_string(MOND_INDEX_WATCHDOGENABLE, FUNC_ENABLE, szErrMsg);
	}
	else	
	{
		set_conf_type_of_string(MOND_INDEX_WATCHDOGENABLE, FUNC_DESABLE, szErrMsg);
	}
	
	return ret;
}

/*
 * do_get_target_containerlist
 */
int do_get_target_containerlist(LPSOCKETINFO new_sockfd, struct _ROT_CMD * rot_cmd, char * szresponsedata, char * szErrMsg)
{
	int ret = 0;
	char sData[MAX_BUF_SIZE] = {0};
	char *sRetBuf;
	memset (&sData, 0x00 , sizeof (sData));
	sprintf (sData, "%s",get_conf_type_of_string(MOND_INDEX_TAR_CONTAINER,szErrMsg));

	sRetBuf = make_response_json_v2(rot_cmd->sCmd, "000000", rot_cmd->sTrid, "success", "watchd_target_containers" , sData, PSRS_TYPE_KEY_ALLINONE );
        sprintf (szresponsedata, "%s", sRetBuf );

	return 1;
}

/*
 * do_set_target_containerlist
 */
int do_set_target_containerlist(LPSOCKETINFO new_sockfd, struct _ROT_CMD * rot_cmd, char * szresponsedata, char * szErrMsg)
{
	int ret = 0;
        
        set_conf_type_of_string(MOND_INDEX_TAR_CONTAINER, 
		(char *)json_object_get_string( json_object_object_get( rot_cmd->pDataObject, "watchd_target_containers")), szErrMsg);
        
	return ret;
}

/*
 * do_get_target_daemonlist
 */
int do_get_target_daemonlist(LPSOCKETINFO new_sockfd, struct _ROT_CMD * rot_cmd, char * szresponsedata, char * szErrMsg)
{
	int ret = 0;
        char sData[MAX_BUF_SIZE] = {0};
        char *sRetBuf;
        memset (&sData, 0x00 , sizeof (sData));
        sprintf (sData, "%s",get_conf_type_of_string(MOND_INDEX_TAR_DAEMON,szErrMsg));

        sRetBuf = make_response_json_v2(rot_cmd->sCmd, "000000", rot_cmd->sTrid, "success", "watchd_target_darmons" , sData, PSRS_TYPE_KEY_ALLINONE );
        sprintf (szresponsedata, "%s", sRetBuf );
        return ret;	
}

/*
 * do_set_target_daemonlist
 */
int do_set_target_daemonlist(LPSOCKETINFO new_sockfd, struct _ROT_CMD * rot_cmd, char * szresponsedata, char * szErrMsg)
{
        int ret = 0;

        set_conf_type_of_string(MOND_INDEX_TAR_CONTAINER,
                (char *)json_object_get_string( json_object_object_get( rot_cmd->pDataObject, "watchd_target_darmons")), szErrMsg);

        return ret;
}

/*
 * do_get_use_cpuinfo
 */
int do_get_use_cpuinfo(LPSOCKETINFO new_sockfd, struct _ROT_CMD * rot_cmd, char * szresponsedata, char * szErrMsg)
{
        int ret = 0;
	char sData[MAX_BUF_SIZE] = {0};
	char szLineBuf[1024] = {0};
	char *ptr;
	char *sRetBuf;
	CPU_P *CP;

	if ((CP=cpu_dfopen()) == NULL)
	{
		do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "cpu_dfopen fail...");
		// error
		return -1;
	}

	while (cpu_dfget(CP))
	{

		if (CP != NULL )	{
			memset (&szLineBuf , 0x00 , sizeof (szLineBuf ));
			sprintf (szLineBuf , "%s|%.2f %%;", CP->cpuname, (float)(CP->cpu_user + CP->cpu_nice + CP->cpu_system) / (CP->cpu_user + CP->cpu_nice + CP->cpu_system + CP->cpu_idle) * 100);
			strncat(sData, szLineBuf, strlen (szLineBuf));	
		}
	}

	cpu_dfclose(CP);

	sRetBuf = make_response_json_v2(rot_cmd->sCmd, "000000", rot_cmd->sTrid, "success", NULL , sData, PARS_TYPE_KEYVALUE );
        sprintf (szresponsedata, "%s", sRetBuf );	
        return ret;
}

/*
 * do_get_totaluse_cpuinfo
 */
int do_get_totaluse_cpuinfo(LPSOCKETINFO new_sockfd, struct _ROT_CMD * rot_cmd, char * szresponsedata, char * szErrMsg)
{
	int ret = 0;
        char sData[MAX_BUF_SIZE] = {0};
        char *ptr;
	char * sRetBuf;
        CPU_P *CP;

	do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "do_get_totaluse_cpuinfo call...");
        if ((CP=cpu_dfopen()) == NULL)
        {
		do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "cpu_dfopen fail...");
                // error
                return -1;
        }

        while (cpu_dfget(CP))
        {
		if (strcmp (CP->cpuname, "cpu") == 0 )		{
	                ptr = strncat("%s;%.2f %%|", CP->cpuname, (float)(CP->cpu_user + CP->cpu_nice + CP->cpu_system) / (CP->cpu_user + CP->cpu_nice + CP->cpu_system + CP->cpu_idle) * 100);
			break;
		}

        }

        cpu_dfclose(CP);

        sprintf (sData, "%s", ptr);
        sRetBuf = make_response_json_v2(rot_cmd->sCmd, "000000", rot_cmd->sTrid, "success", NULL , sData, PARS_TYPE_KEYVALUE );
        sprintf (szresponsedata, "%s", sRetBuf );

        return ret;
}

/*
 * do_get_use_meminfo
 */
int do_get_use_meminfo(LPSOCKETINFO new_sockfd, struct _ROT_CMD * rot_cmd, char * szresponsedata, char * szErrMsg)
{
        int ret = 0;
        char sData[MAX_BUF_SIZE] = {0};
	char szLineBuf [ 1024] = {0};
        char *ptr;
	char *sRetBuf;

        MEM_P *MP;
        if ((MP=mem_dfopen()) == NULL)
        {
		//do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "mem_dfopen fail.....");
                // error
                return -1;
        }

        while (mem_dfget(MP))
        {
		sprintf (szLineBuf , "%s|%llu KB;", MP->memname, MP->mem_info);
                strncat(sData, szLineBuf, strlen (szLineBuf));
        }

        mem_dfclose(MP);
        sRetBuf = make_response_json_v2(rot_cmd->sCmd, "success", rot_cmd->sTrid, "success", NULL , sData, PARS_TYPE_KEYVALUE );

        sprintf (szresponsedata, "%s", sRetBuf );
        return ret;
}

/*
 * do_get_use_diskininfo
 */
int do_get_use_diskininfo(LPSOCKETINFO new_sockfd, struct _ROT_CMD * rot_cmd, char * szresponsedata, char * szErrMsg)
{
	int ret = 0;
        char sData[MAX_BUF_SIZE] = {0};
	char szLineBuf[1024] = {0};
        char *ptr;
	char * sRetBuf;

        PARTITION_P *PRTP;	
        DISKSTAT_P *DSKP;
	char pbuf[1024];

        if ((DSKP=disk_dfopen()) == NULL)
        {
                // error
                return -1;
        }
                 
	if ((PRTP=part_dfopen()) == NULL)
	{
		return -1;
	}

	while(fgets(pbuf, 1023, PRTP->fp))
        {
                sscanf(pbuf, "%s%s%s%s",PRTP->temp1, PRTP->temp1, PRTP->temp1, PRTP->partname);

                while(disk_dfget(DSKP))
                {
                    if(strcmp(DSKP->diskname,PRTP->partname)==0)
                    {
			sprintf (szLineBuf , "%s|%lu %lu;", DSKP->diskname, DSKP->red_sectr, DSKP->wrt_sect);
			strncat(sData , szLineBuf, strlen (szLineBuf) );
                    }
                }
        }

	part_dfclose(PRTP);
	disk_dfclose(DSKP);       

        sRetBuf = make_response_json_v2(rot_cmd->sCmd, "000000", rot_cmd->sTrid, "success", NULL , sData, PARS_TYPE_KEYVALUE );

        sprintf (szresponsedata, "%s", sRetBuf );
        return ret;
}

/*
 *
 */
int process_command(LPSOCKETINFO new_sockfd)
{
	int ret = 0, nCnt = 0, iCommand = 0, nMoreData = 0;
	struct _ROT_CMD rot_cmd;
    char buf[MAX_BUF_SIZE] = {0};
    char szPamMode[128] = {0};
    char szSendData[MAX_BUF_SIZE] = {0};
    char szSendBuf[MAX_HADERDATA_SIZE + MAX_BYDY_LEN] = {0};
    char szResponseData[MAX_HADERDATA_SIZE + MAX_BYDY_LEN] = {0};
    char szErrMsg[1024] = {0};
	char szLogMsg[1024] = {0};

	do
    	{
		if (read_data(new_sockfd, &rot_cmd) != TRUE)
        	{
            		perror("recv");
            		exit(1);
        	}

			iCommand = atoi(rot_cmd.sTrid);

        	switch (iCommand)
        	{
			case CMD_PAM_GET_OP_MODE:
			{
				//sprintf(szLogMsg, "%s",make_log_msg(REQ_MSG, get_ipadddr_for_socket(new_sockfd->iSocket), rot_cmd.sTrid, "get pam op mode" ,"000000", json_object_get_string(rot_cmd.pDataObject)));
				//db_log(LV_INFO, szLogMsg);
				ret = do_get_pam_opmode(new_sockfd, &rot_cmd, szResponseData, szErrMsg);
                if (ret == TRUE)
                {
                    sprintf (szSendData, "%s", szResponseData);
                    do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "successfully collected the pam configuration information.");
                }
				else
				{
					do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "fail to collected the pam configuration information.");
				}				

				sprintf (szSendData, "%s", szResponseData);
			}
			break;

			case CMD_PAM_SET_OP_MODE:
			{
				sprintf(szLogMsg, "%s",make_log_msg(REQ_MSG, get_ipadddr_for_socket(new_sockfd->iSocket), rot_cmd.sTrid, "set pam op mode" ,"000000", json_object_get_string(rot_cmd.pDataObject)));
				db_log(LV_INFO, szLogMsg);
				ret = do_set_pam_opmode(new_sockfd, &rot_cmd, szResponseData, szErrMsg);
				if (ret == TRUE)
                {
                        sprintf (szSendData, "%s", szResponseData);
                        do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__,  "successfully setting the pam access rule information.");
                }

				sprintf (szSendData, "%s", szResponseData);
			}
			break;

			case CMD_PAM_GET_RULE:
			{
				sprintf(szLogMsg, "%s",make_log_msg(REQ_MSG, get_ipadddr_for_socket(new_sockfd->iSocket), rot_cmd.sTrid, "get pam rule" ,"000000", json_object_get_string(rot_cmd.pDataObject)));
				db_log(LV_INFO, szLogMsg);
				ret = do_get_pam_ruleV2(new_sockfd, &rot_cmd, szResponseData, szErrMsg);
                if (ret == TRUE)
                {
                        sprintf (szSendData, "%s", szResponseData);
                        do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__,  "successfully collected the pam access rule information.");
                }

				sprintf (szSendData, "%s", szResponseData);

			}
			break;

			case CMD_PAM_SET_RULE:
			{
				sprintf(szLogMsg, "%s",make_log_msg(REQ_MSG, get_ipadddr_for_socket(new_sockfd->iSocket), rot_cmd.sTrid, "set pam rule" ,"000000", json_object_get_string(rot_cmd.pDataObject)));
				db_log(LV_INFO, szLogMsg);
				ret = do_set_pam_rule (new_sockfd, &rot_cmd, szResponseData, szErrMsg);
                if (ret == TRUE )
                {
                        do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__,  "successfully configuration the pam access rule information.");
                }

				sprintf (szSendData, "%s", szResponseData);

			}
			break;

			case CMD_PAM_ADD_RULE:
			{
				sprintf(szLogMsg, "%s",make_log_msg(REQ_MSG, get_ipadddr_for_socket(new_sockfd->iSocket), rot_cmd.sTrid, "add pam rule" ,"000000", json_object_get_string(rot_cmd.pDataObject)));
				db_log(LV_INFO, szLogMsg);
				ret = do_add_pam_rule(new_sockfd, &rot_cmd, szResponseData, &nMoreData, szErrMsg);
				if (ret == TRUE )
                {
                    do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__,  "successfully configuration the pam access rule information.");
                }
				else
				{
					do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__,  "fail to configuration the pam access rule information.(%s)", szErrMsg);
				}

				//szSendData = make_response_json_v2(rot_cmd.sCmd, "000000", rot_cmd.sTrid, "success", "pam_rule_data", "success", PARS_TYPE_ALLINONE);
				sprintf (szSendData, "%s", szResponseData);
			}
			break;

			case CMD_PAM_DEL_RULE:
			{
				sprintf(szLogMsg, "%s",make_log_msg(REQ_MSG, get_ipadddr_for_socket(new_sockfd->iSocket), rot_cmd.sTrid, "del pam rule" ,"000000", json_object_get_string(rot_cmd.pDataObject)));
				db_log(LV_INFO, szLogMsg);
				ret = do_del_pam_rule(new_sockfd, &rot_cmd, szResponseData, &nMoreData,szErrMsg);
				if (ret == TRUE )
                {
                    do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__,  "successfully configuration the pam access rule information.");
                }
				else
				{
					do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__,  "fail to configuration the pam access rule information.(%s)",szErrMsg);
				}

				sprintf (szSendData, "%s", szResponseData);
			}
			break;

			////////////////////

			case CMD_FW_ADD_RULE:
			{
				sprintf(szLogMsg, "%s",make_log_msg(REQ_MSG, get_ipadddr_for_socket(new_sockfd->iSocket), rot_cmd.sTrid, "add fw rule" ,"000000", json_object_get_string(rot_cmd.pDataObject)));
				db_log(LV_INFO, szLogMsg);

				ret = do_appand_ipf_rule(new_sockfd, &rot_cmd, szResponseData, &nMoreData, szErrMsg);
				if (ret == TRUE)
				{
                    do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__,  "successfully appand ipf rule.");
				}
				else
				{
					do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__,  "fail to successfully appand ipf rule.(%s)", szErrMsg);
				}

				sprintf (szSendData, "%s", szResponseData);
			}
			break;

			case CMD_FW_DEL_RULE:
			{
				sprintf(szLogMsg, "%s",make_log_msg(REQ_MSG, get_ipadddr_for_socket(new_sockfd->iSocket), rot_cmd.sTrid, "del fw rule" ,"000000", json_object_get_string(rot_cmd.pDataObject)));
				db_log(LV_INFO, szLogMsg);
				ret = do_delete_ipf_rule(new_sockfd, &rot_cmd, szResponseData,&nMoreData, szErrMsg);
				if (ret == TRUE)
				{
                        do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__,  "successfully delete ipf rule(%s).",szResponseData);
				}

				sprintf (szSendData, "%s", szResponseData);
			}
			break;

			case CMD_FW_INS_RULE:
			{
				sprintf(szLogMsg, "%s",make_log_msg(REQ_MSG, get_ipadddr_for_socket(new_sockfd->iSocket), rot_cmd.sTrid, "insert fw rule" ,"000000", json_object_get_string(rot_cmd.pDataObject)));
				db_log(LV_INFO, szLogMsg);

				ret = do_insert_ipf_rule(new_sockfd, &rot_cmd, szResponseData, &nMoreData, szErrMsg);
				if (ret == TRUE)
				{
                        do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__,  "successfully insert ipf rule.");
				}
				
				sprintf (szSendData, "%s", szResponseData);
/*
				if (nMoreData == 1)
				{
					if (szSendData != NULL && strlen (szSendData) > 0 && szSendData[0] != '\0')
					{
						if (send(new_sockfd->iSocket, szSendData, strlen(szSendData) + 1, 0) == -1)
						{
								do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "fail to send message...[%d]", errno);
						}
					}

					continue;
				}
*/
			}

			break;

			case CMD_FW_INS_RULE_WITHOUT_DEF:
			{
				sprintf(szLogMsg, "%s",make_log_msg(REQ_MSG, get_ipadddr_for_socket(new_sockfd->iSocket), rot_cmd.sTrid, "insert fw rule" ,"000000", json_object_get_string(rot_cmd.pDataObject)));
				db_log(LV_INFO, szLogMsg);

				ret =  do_insert_ipf_rule_without_default(new_sockfd, &rot_cmd, szResponseData, &nMoreData, szErrMsg);
				if (ret == TRUE)
				{
                        do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__,  "successfully insert ipf rule.");
						do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__,  "successfully insert ipf rule.(%s)",szResponseData);
						do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__,  "successfully insert ipf rule.(%d)",nMoreData);
				}

				sprintf (szSendData, "%s", szResponseData);


				/*if (nMoreData == 1)
				{
					if (szSendData != NULL && strlen (szSendData) > 0 && szSendData[0] != '\0')
					{
						if (send(new_sockfd->iSocket, szSendData, strlen(szSendData) + 1, 0) == -1)
						{
								do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "fail to send message...[%d]", errno);
						}
					}

					continue;
				}
				*/

			}
			break;

			case CMD_FW_SET_RULE:
			{
				sprintf(szLogMsg, "%s",make_log_msg(REQ_MSG, get_ipadddr_for_socket(new_sockfd->iSocket), rot_cmd.sTrid, "set fw rule" ,"000000", json_object_get_string(rot_cmd.pDataObject)));
				db_log(LV_INFO, szLogMsg);

				ret = do_set_ipf_rule (new_sockfd, &rot_cmd, szResponseData, szErrMsg);
                if (ret == TRUE )
                {
                        do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__,  "successfully configuration the pam access rule information.");
                }

				sprintf (szSendData, "%s", szResponseData);
				//do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "szSenmdData : %s", szSendData);

			}
			break;


			case CMD_MOND_GET_MODDE:
			{
				sprintf(szLogMsg, "%s",make_log_msg(REQ_MSG, get_ipadddr_for_socket(new_sockfd->iSocket), rot_cmd.sTrid, "get watch op mode" ,"000000", json_object_get_string(rot_cmd.pDataObject)));
				db_log(LV_INFO, szLogMsg);
				ret = do_get_monD_mode(new_sockfd, &rot_cmd, szResponseData, szErrMsg);
				if (szResponseData == NULL)
				{
				}

				if (ret == TRUE )
				{
					memset (szLogMsg, 0x00, sizeof (szLogMsg));
					sprintf(szLogMsg, "%s",make_log_msg(RES_MSG, get_ipadddr_for_socket(new_sockfd->iSocket), rot_cmd.sTrid,"get watch op mode", "000000", "success."));
					do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, szLogMsg);
				}
				else
				{
					memset (szLogMsg, 0x00, sizeof (szLogMsg));
                                        sprintf(szLogMsg, "%s",make_log_msg(RES_MSG, get_ipadddr_for_socket(new_sockfd->iSocket), rot_cmd.sTrid,"get watch op mode", "000001", "fail"));
                                        do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, szLogMsg);
				}
				sprintf (szSendData, "%s", szResponseData);
			}
			break;
		
			case CMD_MOND_SET_MODDE:			
			{
				ret = do_set_monD_mode(new_sockfd, &rot_cmd, szResponseData, szErrMsg);
			}
			break;

			case CMD_MOND_GET_TARCONTAINERLIST:
			{
				memset (szLogMsg, 0x00, sizeof (szLogMsg));
				sprintf(szLogMsg, "%s",make_log_msg(REQ_MSG, get_ipadddr_for_socket(new_sockfd->iSocket), rot_cmd.sTrid, "get monitoring Target Container list", "000000", ""));
				db_log(LV_INFO, szLogMsg);
				ret = do_get_target_containerlist(new_sockfd, &rot_cmd, szResponseData, szErrMsg);
				if (szResponseData == NULL )		{
					memset (szLogMsg, 0x00, sizeof (szLogMsg));
                                        sprintf(szLogMsg, "%s",make_log_msg(RES_MSG, get_ipadddr_for_socket(new_sockfd->iSocket), rot_cmd.sTrid,"get monitoring Target Container list", "000001", "fail"));
				}
				else
				{
					memset (szLogMsg, 0x00, sizeof (szLogMsg));
                                        sprintf(szLogMsg, "%s",make_log_msg(RES_MSG, get_ipadddr_for_socket(new_sockfd->iSocket), rot_cmd.sTrid,"get monitoring Target Container list", "000000", "success."));
				}
				db_log(LV_INFO, szLogMsg);
				
				sprintf (szSendData, "%s", szResponseData);
			}
			break;

			case CMD_MOND_SET_TARCONTAINERLIST:
			{
				ret = do_set_target_containerlist(new_sockfd, &rot_cmd, szResponseData, szErrMsg);				
			}
			break;

			case CMD_MOND_GET_TARDAEMONLIST:
			{
				ret = do_get_target_daemonlist(new_sockfd, &rot_cmd, szResponseData, szErrMsg);
				sprintf (szSendData, "%s", szResponseData);
			}
			break;

			case CMD_MOND_SET_TARDAEMONLIST:
			{
				ret = do_set_target_daemonlist(new_sockfd, &rot_cmd, szResponseData, szErrMsg);
			}
			break;

			case CMD_MOND_GET_CPUINFO:
			{
				ret = do_get_use_cpuinfo(new_sockfd, &rot_cmd, szResponseData, szErrMsg);
				sprintf (szSendData, "%s", szResponseData);
			}
			break;

			case CMD_MOND_GET_MEMINFO:
			{
				ret = do_get_use_meminfo(new_sockfd, &rot_cmd, szResponseData, szErrMsg);
				sprintf (szSendData, "%s", szResponseData);
			}
			break;

			case CMD_MOND_GET_DISKIOINFO:
			{
				ret = do_get_use_diskininfo(new_sockfd, &rot_cmd, szResponseData, szErrMsg);
				sprintf (szSendData, "%s", szResponseData);
			}
			break;
			
			default:
			{
				snprintf(szSendData, MAX_BUF_SIZE, "Bad request....(%d/%d)",iCommand,CMD_FW_INS_RULE);	
			}
			break;			
		}
		
	
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

		if (nMoreData == 0 )
		 	break;

	}while (1);

	
	return ret;
}

/*
 *
 */
int process_command_for_fork(int nCommType)
{

	//init_log2();
	printf ("run process_command...\n");
	switch (nCommType)
	{
		case (int) MOND_COMM_CONTAINER:
			start_container_watchdog();
		break;

		case (int) MOND_COMM_PID:
			start_pid_watchdog();
		break;

		case (int) MOND_COMM_WD:
			start_wd_watchdog();
		break;
		
		default:
		break;
	}

	return 0;
}
