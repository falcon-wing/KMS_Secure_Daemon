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
#include <curl/curl.h>
#include <json-c/json.h>
#include <ctype.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/prctl.h>
#include <limits.h>
#include "def.h"
#include "utils.h"

#include "mon_log.h"

char g_szRootPath[MAX_FULLPATH_SIZE + 1] = {0};
char *g_pcSERVER_ADDR = (char *)NULL;
BOOL g_nInitSecureLog = FALSE;

//char g_szIdent[MAX_LOG_IDENT_SIZE + 1] = "\0";
char g_szLogFilename[MAX_FULLPATH_SIZE + 1] = {0};
char g_szLockFilename[MAX_FULLPATH_SIZE + 1] = "\0";

int g_nMaxLogSize = 0;
int g_nMaxLogFileCount = 0;
int g_nRCLogRotate = 0;
char g_szIdent[MAX_LOG_IDENT_SIZE + 1] = "\0";

//<>
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

int chk_tar_container_by_name(char * szTarContainers, char * szDockerUrl)
{
	if (szTarContainers == NULL )
        {
                return false;
        }

	json_object *json;
	CURL *curl;
        curl_global_init(CURL_GLOBAL_ALL);
	struct memory chunk = {0};
        struct ContainerState * status = NULL;
	int i = 0, nTarCnt = 0;
	char ** ppTarList;
        char szLineBuf[1024] = {0}, url[1024] = {0};
        status = (struct ContainerState *) malloc (sizeof (struct ContainerState));

	nTarCnt = split(szTarContainers, ';', &ppTarList);
	if (nTarCnt == 0 || ppTarList == NULL)
        {
                return false;
        }

	for (i = 0 ; i < nTarCnt ; i ++ )
	{
		curl = curl_easy_init();
		if (curl)
		{
			memset (&chunk, 0, sizeof (chunk));
			memset (&url, 0, sizeof (url));
			if (strlen (ppTarList[i]) <= 0  || ppTarList[i][0] == 0x00 )
			{
				sleep (2);
				continue;
			}

			sprintf (url, "%s/containers/%s/json", szDockerUrl, ppTarList[i]);

			curl_easy_setopt(curl, CURLOPT_URL, url);
			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cb);
			curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *) &chunk);
			curl_easy_perform(curl);
			curl_easy_cleanup(curl);
			if (chunk.response )
			{
				memset (status, 0, sizeof (status));
				json = json_object_new_object();
				if (deserialization_struct_to_containerJson(chunk.response, status ) == 1 )
				{
					if (status->Running == true)
                                        {
					}
					else
					{
						do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__,"We've detected the monitoring target container's termination.Now, we'll restart the monitoring target - [%s].", ppTarList[i]);
						RunTargetContainer(ppTarList[i]);
					}

				}
				else
				{
					do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__,"We've detected the monitoring target container's termination.Now, we'll restart the monitoring target - [%s].", ppTarList[i]);
					RunTargetContainer(ppTarList[i]);
				}

      			 	json_object_put(json);

			}

		}

	//	free (ppTarList);

		
	}

	free (ppTarList);
	curl_global_cleanup();
	return true;
}

//<>
int chk_tar_daemon_by_pid( char * szTarDaemons)
{
	if (szTarDaemons == NULL )
	{
		return false;
	}
	char ** ppTarList;
	char szDName[NAME_MAX] = {0}, szPath[PATH_MAX] = {0}, szTarExecPath[PATH_MAX] = {0};
	char szTmp[MAX_FULLPATH_SIZE] = {0}, szTargetpidFileFullPath[MAX_FULLPATH_SIZE] = {0};
	char szMasterDaemonPidFile[MAX_FULLPATH_SIZE] = {0}, szMasterDaemonFile[MAX_FULLPATH_SIZE] = {0};

	
	int i = 0, ret = 0;

	//
	// MONADMIN_DAEMON
	snprintf (szMasterDaemonPidFile, MAX_FULLPATH_SIZE, "%s/etc/%s.pid", ROOT_PATH, MONADMIN_DAEMON);
	snprintf (szMasterDaemonFile, MAX_FULLPATH_SIZE, "%s/%s", ROOT_PATH, MONADMIN_DAEMON);
	if ((is_file(szMasterDaemonPidFile)) == TRUE)
	{
		int pid = get_pid(szMasterDaemonPidFile);
		if (pid == E_RET )
		{
			//ERROR MESSAGE
		}
		else
		{
			if((find_process(pid, MONADMIN_DAEMON)) != TRUE)
			{
				if ((do_cmd_set(MONADMIN_DAEMON, szMasterDaemonFile)) == TRUE )
                                {
                                        //SUCCESS LOG
					do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "target process(daemon) [%s] has been successfully restarted.", MONADMIN_DAEMON);
                                        return true;

                                }
                                else
                                {
                                        //FAIL LOG
					do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "The target process [%s] restart has failed.", MONADMIN_DAEMON);
                                        return false;
                                }
			}
		}
	}
		
	//

	int nTarCnt = split(szTarDaemons, ';', &ppTarList);
	if (nTarCnt == 0 || ppTarList == NULL)
	{
		return false;
	}

	for (i = 0 ; i < nTarCnt ; i ++ )
	{
		if (ppTarList[i] == NULL || ppTarList[i][0] == 0x00 || strlen(ppTarList[i]) <= 0)
		{
			sleep(2);
			continue;
		}

		sprintf (szTmp, "%s", ppTarList[i]);

		char * Data = strtok(szTmp, "|");
                sprintf (szDName, "%s", Data);
                Data = strtok(NULL, "|");
                sprintf (szPath, "%s", Data);
		
		snprintf(szTargetpidFileFullPath, MAX_FULLPATH_SIZE, "%s/etc/%s.pid", ROOT_PATH, szDName);
		if ((is_file(szTargetpidFileFullPath)) == TRUE)
		{
			int pid = get_pid(szTargetpidFileFullPath);
			if (pid == E_RET)
			{
				sleep(2);
				continue;
			}

			if((find_process(pid, szDName)) != TRUE)
			{
				memset (szTarExecPath, 0x00 ,PATH_MAX);
				sprintf (szTarExecPath, "%s/%s", szPath, szDName);
				
				if ((do_cmd_set(szDName, szTarExecPath)) == TRUE )
				{
					//SUCCESS LOG
					do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "target process(daemon) [%s] has been successfully restarted.", szDName);
					return true;
					
				}
				else
				{
					//FAIL LOG
					do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "The target process [%s] restart has failed.", szDName);
					return false;
				}
			}
		}

		sleep(2);		
	}
	return false;
}

int main (int argc, char ** argv )
{
	int ret = 0;
	char szErrMsg[1024] = {0};
	char szDConfFilePath[MAX_FULLPATH_SIZE] = {0},szDConfDir[MAX_FULLPATH_SIZE] = {0};
	char szWdpidFilePath[MAX_FULLPATH_SIZE] = {0},szDLogFilePath[MAX_FULLPATH_SIZE] = {0};

	snprintf(szDConfDir, MAX_FULLPATH_SIZE - 1, "%s/%s", ROOT_PATH, ROT_CONF);
	snprintf(szDConfFilePath, MAX_FULLPATH_SIZE, "%s/%s", szDConfDir, ROT_DCONFILE);
	snprintf(szWdpidFilePath, MAX_FULLPATH_SIZE -1 , "%s/%s/%s.pid", ROOT_PATH,ETC_DIR,MAINDAEMON_PRODUCTNAME);
	snprintf(szDLogFilePath, MAX_FULLPATH_SIZE -1 , "%s/%s/%s",ROOT_PATH, ROT_LOGDIR, ROT_LOGFILE2);
	umask(022);
	//ret = rotdconf_read_conf(szDConfFilePath);

	InitRotLog(IDENT_DEFAULT, szDLogFilePath, get_bytetoMbyte(50), 5, 1);

	//do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__," wd_worker.c log test 001.");
	//do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__," wd_worker.c log test 002.");
	//do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__," wd_worker.c log test 003.");
	daemonization();
        SetSignal();

	already_running(szWdpidFilePath);

	while (1)
	{
		//
		monDLogconf_t conf;
                memset (&conf, 0x00, sizeof (conf ));
                get_monD_conf(&conf, szErrMsg);
		if (conf.cWatchDogEnable != 'Y')
		{
			sleep(10);
			continue;
		}
		//

		//<chk target pid>
		chk_tar_daemon_by_pid(conf.szTargetDaemon);
		
		//<chk target container>
		chk_tar_container_by_name(conf.szTargetContainer, conf.szDockerUrl);
		
		//
		sleep (10);
	}

	return ret;
}
