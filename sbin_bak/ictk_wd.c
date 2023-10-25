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
#include <ctype.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/prctl.h>
#include <stdbool.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include "ictk_wd.h"
#include "def.h"
#include "conf.h"
#include "mon_log2.h"
//#include "mon_log.h"
#include "utils.h"

char g_szRootPath[MAX_FULLPATH_SIZE + 1] = {0};
char *g_pcSERVER_ADDR = (char *)NULL;
BOOL g_nInitSecureLog = FALSE;
char g_szLogFilename[MAX_FULLPATH_SIZE + 1] = {0};
char g_szLockFilename[MAX_FULLPATH_SIZE + 1] = "\0";

int g_nMaxLogSize = 0;
int g_nMaxLogFileCount = 0;
int g_nRCLogRotate = 0;
char g_szIdent[MAX_LOG_IDENT_SIZE + 1] = "\0";
static const char data[]="";

bool g_bDaemonwork = false, g_bContainerwork = false;

#ifndef E_RET
#define E_RET	 -1
#endif

#ifndef FALSE
#define FALSE	 0
#endif

void do_log2(int level, char * fmt, ...);

#define LOCKMODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

#ifndef TRUE
#define TRUE	 1
#endif

#ifndef ICTK_ROOT_PATH 
#define ICTK_ROOT_PATH "/usr/local/ictk"
#endif

#ifndef ICTK_ETC_DIR
#define ICTK_ETC_DIR	"etc"
#endif

#ifndef ICTK_CONF_DIR
#define ICTK_CONF_DIR 	"conf"
#endif

#ifndef ICTK_CONF_FILE
#define ICTK_CONF_FILE	"monD.conf"
#endif



#ifndef MON_TARGET_D_LIST_KEY 
#define MON_TARGET_D_LIST_KEY 	"MOND_TARGET_DAEMON" 
#endif

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

void stat2proc(char*S, struct ProcInfo *P) {
        char* tmp = strrchr(S, ')');            /* split into "PID (cmd" and "<rest>" */
        *tmp = '\0';                                            /* replace trailing ')' with NUL */
        /* parse these two strings separately, skipping the leading "(". */
        memset(P->cmd, 0, sizeof P->cmd);   /* clear even though *P xcalloc'd ?! */
        sscanf(S, "%d (%39c", &P->pid, P->cmd);
        sscanf(tmp + 2,                                  /* skip space after ')' too */
                "%c %d %d %d %d %d %lu %lu %lu %lu %lu %ld %ld %ld %ld %d "
                "%d %lu %lu %ld %lu %lu %lu %lu %lu %lu %lu %lu %LX %LX %LX %LX %lu",
                &P->state, &P->ppid, &P->pgrp, &P->session, &P->tty, &P->tpgid,
                &P->flags, &P->min_flt, &P->cmin_flt, &P->maj_flt, &P->cmaj_flt,
                &P->utime, &P->stime, &P->cutime, &P->cstime, &P->priority, &P->nice,
                &P->timeout, &P->it_real_value, &P->start_time, &P->vsize, &P->rss,
                &P->rss_rlim, &P->start_code, &P->end_code, &P->start_stack,
                &P->kstk_esp, &P->kstk_eip, &P->signal, &P->blocked, &P->sigignore,
                &P->sigcatch, &P->wchan);

                if (P->tty == 0)
                        P->tty = -1;  /* the old notty val, update elsewhere bef. moving to 0 */
}

static int is_file(char *path)
{
        int ret;
        struct stat st;

        ret = stat(path, &st);
        if (ret < 0)
                return E_RET;

        if (S_ISREG(st.st_mode))
                return TRUE;
        else
                return FALSE;
}

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

char *strip_whitechar(char *buf)
{
        int flag=1;
        char *tp;

        tp = NULL;

        if (buf == NULL)
                return NULL;

        while(*buf)
        {
                if (isspace((int)*buf))
                {
                        if (flag == 2)
                        {
                                buf = NULL;
                                flag = 0;
                                break;
                        }
                }
                else
                {
                        if (flag == 1)
                        {
                                tp = buf;
                                flag = 2;
                        }
                }

                *buf++;
        }

        if (flag != 1)
                return tp;

        return NULL;
}


void daemon_init()
{
        int     nFd;
        const int nMaxFd = 64;
        pid_t nPid;

        nPid = fork();
        if ( nPid < 0 )
                exit(1);

        if ( nPid > 0 ) /* parent process teminates */
                exit(0);

        setsid();

        nPid = fork();
        if ( nPid < 0 )
                exit(1);

        if ( nPid > 0 ) /* parent process teminates */
                exit(0);

        chdir("/");
        umask(0);

        /* close out the standard file descriptors */
        freopen("/dev/null", "r", stdin);
        freopen("/dev/null", "w", stdout);
        freopen("/dev/null", "w", stderr);

        /* close all file descriptor */
        for (nFd=3; nFd<nMaxFd; nFd++)
                close(nFd);
}

void sig_term(int sig){
        //g_nShutdown = 1;
}

void sig_hup(int sig){
        //g_nReConfig = 1;
}

void SetSignal(){
        struct sigaction sa;

        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;

        sa.sa_handler = sig_term;
        sigaction(SIGTERM, &sa, NULL);

        sa.sa_handler = sig_hup;
        sigaction(SIGHUP, &sa, NULL);

        sa.sa_handler = SIG_IGN;
        sigaction(SIGINT, &sa, NULL);
}

int is_num_v2(char *arg)
{
        int i;

        if (*arg == 0x00)
	{
                return FALSE;
	}

        for (i=0 ; *(arg+i) != NULLC ; i++)
        {
                if (i == 0)
                {
                        if (!isdigit((int)*arg) && (*arg != '-'))
			{
                                return FALSE;
			}
                }
                else
                {
                        if (!isdigit((int)*(arg+i)))
			{
                                return FALSE;
			}
                }
        }

        return TRUE;
}

int is_num(char *arg)
{
        int i;

        if (*arg == 0x00)
                return FALSE;

        for (i=0 ; *(arg+i) != 0 ; i++)
        {
                if (i == 0)
                {
                        if (!isdigit((int)*arg) && (*arg != '-'))
                                return FALSE;
                }
                else
                {
                        if (!isdigit((int)*(arg+i)))
			{
                                return FALSE;
			}
                }
        }

        return TRUE;
}

pid_t get_pid(char *szPidPath)
{
	FILE *fp;
        char buf[20];
        char *szPid;

        fp = fopen(szPidPath, "r");
        if (fp == NULL)
        {
                return E_RET;
        }

        if (fgets(buf, 20, fp))
        {
                szPid = strip_whitechar(buf);
                if (szPid == NULL)
                {
                        fclose(fp);
                        return E_RET;
                }

		if (szPid[strlen(szPid)-1] == '\n')
                {
                        szPid[strlen(szPid)-1] = '\0';
                }

                if (is_num(szPid))
                {
                        fclose(fp);
                        return atoi(szPid);
                }
                else
                {
                        fclose(fp);
                        return E_RET;
                }
        }
        else
        {
                fclose(fp);
                return E_RET;
        }
}

int isValidNumber(char *szString)
{
        int i, nLen;

        if ( (szString == NULL) || (szString[0] == '\0') )
                return 0;

        nLen = strlen(szString);

        for (i = 0; i < nLen; i++)
                if ( !isdigit((int)szString[i]) )
                        return 0;

        return 1;
}

int find_process(pid_t nPid, char *szName)
{
        int fd;
        int n;

        struct ProcInfo stProcInfo;

        char flnm[32];
        char buf[1024]; /* primary storage for file io */

        sprintf(flnm, "/proc/%ld/stat", nPid);

        if ((fd = open(flnm, O_RDONLY)) < 0)
                return E_RET;

        if ((n = read(fd, buf, 1024-1)) == -1)
                return E_RET;

        buf[n] = '\0';    /* terminate the string */
        close(fd);

        stat2proc(buf, &stProcInfo);

        if (!strcmp(stProcInfo.cmd, szName) )
                return TRUE;

        return FALSE;

}

int isDaemonDup(char * szPidFilename, char * szExecName)
{
	FILE * fp;
	char szBuf[1024] = {0};

	if (( fp = fopen(szPidFilename, "rt")) != NULL)
	{
		if (fgets(szBuf, 1024, fp) && isValidNumber(szBuf ))
		{
			if (find_process (atoi(szBuf), szExecName) == 1 )
			{
				fclose (fp);
				return 1;
			
			}
		}
		else
		{
			fclose (fp);
			return 0;
		}

	}
	return 0;

}

int do_cmd_set(char *szCmd , char *szFullPath)
{
	int ret, p_stat;
	FILE * fp;
	pid_t pid;
	char szShellPath[MAX_FULLPATH_SIZE] ={0};

	sprintf (szShellPath, "./%s", szCmd);
	if ( 0!= access (szFullPath, F_OK))
	{
		//ERROR MSG
	}

	chdir (ROOT_PATH);

	fp = popen (szShellPath, "r");
	if (fp == NULL )
	{
		//ERROR MSG
		//exit(errno);
		return FALSE;
	}
	pclose(fp);


	return TRUE;
#ifdef _OLD_CMD__
	pid = fork();
	if (pid < 0 )
	{
		exit(0);
		return E_RET;
	}
	
        if (pid == 0 )
	{
		sprintf (szShellPath, "./%s", szCmd);
		if ( 0!= access (szFullPath, F_OK))
		{
			//ERROR MSG			
		}

		chdir (ROOT_PATH);

		fp = popen (szShellPath, "r");
		if (fp == NULL )
		{
			//ERROR MSG
			exit(errno);
		}
		pclose(fp);
		exit (0);
	}
	else
	{
		waitpid(pid, &p_stat);
		if (WIFEXITED(p_stat))
		{
			if (WEXITSTATUS(p_stat) == 0 )
			{
				return TRUE;
			}
			else
			{
				errno = WEXITSTATUS(p_stat);
				return E_RET;
			}
		}

		else
		{
			return FALSE;
		}
	}
#endif //_OLD_CMD__

}
#ifdef _LOG_2__
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

	sprintf (szInfoLogPath, "%s/%s/ictk_wd.01", ICTK_ROOT_PATH, "logs");
	info_fp = fopen (szInfoLogPath, "a+");

	if (info_fp == NULL )
	{
		return ;
	}

	log_add_fp(info_fp, 2);
	log_info(szBuf);

	fclose (info_fp);
}
#endif 

int already_running(char *szPidFile)
{
    int fd;
    char buf[16];

    fd = open(szPidFile, O_RDWR | O_CREAT, LOCKMODE);
    if (fd < 0)
    {
        // syslog(LOG_ERR, "can't open %s: %s", szPidFile, strerror(errno));
        exit(1);
    }

    if (flock(fd, LOCK_EX | LOCK_NB) != 0)
    {

        if (errno == EACCES || errno == EAGAIN)
        {
            close(fd);
            return (1);
        }
        // syslog(LOG_ERR, "can't lock %s: %s", szPidFile, strerror(errno));
        exit(1);
    }
    ftruncate(fd, 0);
    sprintf(buf, "%ld", (long)getpid());
    write(fd, buf, strlen(buf) + 1);
    return (0);
}

int daemon_monitoring( char * szConfFile, char * szMainDaemonPIDFullPath, char *szErrMsg)
{
	int ret = 0, i = 0, pid = 0, nCount = 0;
	char **tarTarName;
        char szBuffer[2048] = {0};
	char szMainDaemonFullPath[MAX_FULLPATH_SIZE + 1 ] = {0};
	char szPIDFileFullPath[MAX_FULLPATH_SIZE + 1 ] = {0};
	char szCheckPIDFilePath[MAX_FULLPATH_SIZE + 1] = {0};

	sprintf (szCheckPIDFilePath, "%s/%s", ICTK_ROOT_PATH, ICTK_ETC_DIR );
	sprintf (szMainDaemonFullPath, "%s/%s", ROOT_PATH, MAINDAEMON_PRODUCTNAME);

	ret = rotdconf_read_conf(szConfFile);
	if (ret == FALSE )              {

		//ERROR MSG
		sleep (1);
		return FALSE;
	}

	ret = rotdconf_get_conf("MOND_WATCHDOG_ENABLE", szBuffer );
	if (strcmp (szBuffer , "YES") != 0 )
	{
		sleep(5);		
		return TRUE;
	}

	memset (szBuffer, 0x00 , sizeof (szBuffer ));
	// first check mond
	ret = rotdconf_get_conf(MON_TARGET_D_LIST_KEY, szBuffer );
	if (ret == FALSE )              {
		//ERROR MSG
		return FALSE;

	}

	if (is_file(szMainDaemonPIDFullPath) == TRUE )
	{
		pid = get_pid(szMainDaemonPIDFullPath);
		if (pid == E_RET )              {
			//ERROR
			
			return FALSE;
		}
		ret = find_process(pid, MAINDAEMON_PRODUCTNAME);
		if (ret != TRUE )
		{
			if (do_cmd_set(MAINDAEMON_PRODUCTNAME, szMainDaemonFullPath) == TRUE )                                  {
				// SUCCESS LOG
				//do_rotlog(WORKDAEMON_PRODUCTNAME, 1, LV_INFO, __FILE__, __LINE__, "target process(daemon) [%s] has been successfully restarted.",MAINDAEMON_PRODUCTNAME);
				do_log2(_LOG_INFO , "target process(daemon) [%s] has been successfully restarted.",MAINDAEMON_PRODUCTNAME);
			}

			else
			{
				//do_rotlog(WORKDAEMON_PRODUCTNAME, 1, LV_INFO, __FILE__, __LINE__, "The target process [%s] restart has failed.", MAINDAEMON_PRODUCTNAME);		
				do_log2( _LOG_INFO,"The target process [%s] restart has failed.", MAINDAEMON_PRODUCTNAME);
			}

		}

	}

	nCount = split (szBuffer, ';', &tarTarName );
	if (tarTarName == NULL )                {
		//ERROR MSG

		return FALSE;
	}

	for (i = 0 ; i < nCount ; i ++ )
	{

		char szItem[MAX_FULLPATH_SIZE] = {0}, szTarName[256] = {0}, szPath[MAX_FULLPATH_SIZE] = {0};
		if (tarTarName[i] == NULL || tarTarName[i][0] == 0x00 || strlen (tarTarName[i] ) <= 0 )                 {
			sleep (1);
			continue;
		}

		memset (szItem, 0x00, sizeof (szItem));
		sprintf (szItem, "%s", tarTarName[i]);
		char * cData = strtok(szItem, "|");
		sprintf (szTarName, "%s", cData);
		cData = strtok(NULL, "|");
		sprintf (szPath, "%s", cData );

		memset (szPIDFileFullPath, 0x00, sizeof (szPIDFileFullPath));

		snprintf (szPIDFileFullPath, MAX_FULLPATH_SIZE, "%s/%s.pid", szCheckPIDFilePath, szTarName);
		if (is_file(szPIDFileFullPath) == TRUE)                 {

			pid = get_pid(szPIDFileFullPath);
			if (pid == E_RET )
			{
				sleep(2);
				continue;
			}
			
			ret = find_process(pid, szTarName);
			if (ret != TRUE )
			{

				if (do_cmd_set(szTarName, szPIDFileFullPath) == TRUE )                                  
				{
					// SUCCESS LOG
					 //do_rotlog(WORKDAEMON_PRODUCTNAME, 1, LV_INFO, __FILE__, __LINE__, "target process(daemon) [%s] has been successfully restarted.",szTarName);
					do_log2(_LOG_INFO, "target process(daemon) [%s] has been successfully restarted.",szTarName);
				}

				else
				{
					// FAILLER LOG
					//do_rotlog(WORKDAEMON_PRODUCTNAME, 1, LV_INFO, __FILE__, __LINE__, "The target process [%s] restart has failed.", szTarName);
					do_log2(_LOG_INFO, "The target process [%s] restart has failed.", szTarName);
				}
			}
		}

		sleep(2);
	}
	return ret;
}

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


int container_monitoring()
{
	do_log2(_LOG_INFO, "container_monitoring...00000ii");
        int ret = 0, i = 0, nTarCnt = 0 ;

        json_object *json;
        curl_global_init(CURL_GLOBAL_ALL);
	do_log2(_LOG_INFO, "container_monitoring...00000ii2");
        CURL *curl;
        struct memory chunk = {0};
        struct ContainerState * status = NULL;
        char szDConfFilePath[MAX_FULLPATH_SIZE] = {0};
        char url[1024] = {0};
        char szWatchDogOpMode[4] = {0};
        char *strCurrPath = NULL;
        char szErrMsg[1024] = {0};
        //strCurrPath = rot_getcwd();
	do_log2(_LOG_INFO, "container_monitoring...00000");
        snprintf(szDConfFilePath, MAX_FULLPATH_SIZE, "%s/%s/%s", ICTK_ROOT_PATH, ROT_CONF, ROT_DCONFILE);

	do_log2(_LOG_INFO, "container_monitoring...");
	do_log2(_LOG_INFO, "container_monitoring::szDConfFilePath [%s]", szDConfFilePath);
        sprintf (url, "http://127.0.0.1:2378/containers/big_boss/json");

        char **tarTarName;
        char szLineBuf[1024] = {0};
        status = (struct ContainerState *) malloc (sizeof (struct ContainerState));
        while (1)
        {
		 do_log2(_LOG_INFO, "container_monitoring::~~~~~~~");
		//do_rotlog(WORKDAEMON_PRODUCTNAME, 1, LV_INFO, __FILE__, __LINE__,">>>>>>>>>>>>>>>>>>");
                monDLogconf_t conf;
                memset (&conf, 0x00, sizeof (conf ));
                get_monD_conf(&conf, szErrMsg);
		//do_rotlog(WORKDAEMON_PRODUCTNAME, 1, LV_INFO, __FILE__, __LINE__,"enable check befor....");
                //do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, "get conf resutl ....[%s][%c]",conf.szTargetContainer, conf.cWatchDogEnable);
                if (conf.cWatchDogEnable != 'Y')
                {
                        sleep(10);
                        continue;
                }
		//do_rotlog(WORKDAEMON_PRODUCTNAME, 1, LV_INFO, __FILE__, __LINE__,"enable check after...");
                nTarCnt = split(conf.szTargetContainer, ';', &tarTarName);

                //do_rotlog(WORKDAEMON_PRODUCTNAME, 1, LV_INFO, __FILE__, __LINE__,"WatchDog Op mode = [%c], con list = [%s] cnt = [%d]", conf.cWatchDogEnable,conf.szTargetContainer,nTarCnt);

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
                                                        //do_rotlog(WORKDAEMON_PRODUCTNAME, 1, LV_INFO, __FILE__, __LINE__,"We've detected the monitoring target container's termination.Now, we'll restart the monitoring target - [%s].", tarTarName[i]);
							do_log2(_LOG_INFO,"We've detected the monitoring target container's termination.Now, we'll restart the monitoring target - [%s].", tarTarName[i]);
                                                        RunTargetContainer(tarTarName[i]);
                                                }
                                        }
                                        else
					{
                                                //do_rotlog(WORKDAEMON_PRODUCTNAME, 1, LV_INFO, __FILE__, __LINE__,"We've detected the monitoring target container's termination. Now, we'll restart the monitoring target - [%s].", tarTarName[i]);
						do_log2(_LOG_INFO, "We've detected the monitoring target container's termination. Now, we'll restart the monitoring target - [%s].", tarTarName[i]);
                                                RunTargetContainer(tarTarName[i]);
                                        }
                                }
                                else
                                {
                                //      printf ("response is null......\n");
                                }

                                //json_object_put(curl);
                        }

                        sleep(1);
                }

                free (tarTarName);

                sleep(1);
        }

        curl_global_cleanup();
        //do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "WatchDog client fin......");

        return ret;
}

void do_log2(int level, char * fmt, ...)
{
	char szLogFilePath[MAX_FULLPATH_SIZE + 1] = {0};
	char buf[2048] = {0};
	int res = 0;
	va_list ap;
	int i;

	sprintf (szLogFilePath, "%s/logs/%s",ROOT_PATH,	ROT_LOGFILE);

	FILE * fp;
	fp = fopen(szLogFilePath, "ab");
	if (fp == NULL )
	{
		printf ("do_log2 --003\n");
		return ;
	}

	log_add_fp(fp, _LOG_INFO);

	va_start(ap, fmt);
	vsprintf(buf, fmt, ap);
	va_end(ap);

	if (level == _LOG_INFO)
	{
		log_info(buf);
	}
	else if (level = _LOG_WARN)
	{
		log_warn(buf);
	}

	
	fclose(fp);

} 

int main (int argc, char ** argv )
{
	FILE * fp;
	FILE * fp_errlog, *fp_infolog;
	int ret = 0, nCount, i, pid;
	pid_t wd_daemon_pid, wd_container_pid;
	char **tarTarName;
	char szBuffer[2048] = {0};
	char szErrMsg[1024] = {0};
	char szCheckPIDFilePath[MAX_FULLPATH_SIZE + 1], szPIDFileFullPath[MAX_FULLPATH_SIZE + 1], szConfFileFullPath[MAX_FULLPATH_SIZE + 1] ;
	char szMainDaemonPIDFullPath[MAX_FULLPATH_SIZE + 1], szErrLogPath[MAX_FULLPATH_SIZE + 1], szInfoLogPath[MAX_FULLPATH_SIZE + 1];
	char szMainDaemonFullPath[MAX_FULLPATH_SIZE + 1 ] = {0};
	char szWorkDaemonPIDFullPath[MAX_FULLPATH_SIZE + 1] = {0}, szWorkDaemonFullPath[MAX_FULLPATH_SIZE +1] = {0};
	char szDLogFilePath[MAX_FULLPATH_SIZE] = {0};
	
	sprintf (g_szRootPath, "%s", ICTK_ROOT_PATH);
	sprintf (szCheckPIDFilePath, "%s/%s", ICTK_ROOT_PATH, ICTK_ETC_DIR );
	sprintf (szMainDaemonPIDFullPath, "%s/%s.pid", szCheckPIDFilePath, MAINDAEMON_PRODUCTNAME);
	sprintf (szConfFileFullPath, "%s/%s/%s", ICTK_ROOT_PATH, ICTK_CONF_DIR,ICTK_CONF_FILE);
	sprintf (szMainDaemonFullPath, "%s/%s", ROOT_PATH, MAINDAEMON_PRODUCTNAME);

	sprintf (szWorkDaemonPIDFullPath, "%s/%s.pid", szCheckPIDFilePath, WORKDAEMON_PRODUCTNAME);
	sprintf (szWorkDaemonFullPath , "%s/%s", ROOT_PATH, WORKDAEMON_PRODUCTNAME);
	
	snprintf(szDLogFilePath, MAX_FULLPATH_SIZE, "%s/%s/%s", ROOT_PATH,ROT_LOGDIR, ROT_LOGFILE);

	do_log2(_LOG_INFO, "TEST000000000000000");

	ret = rotdconf_read_conf(szConfFileFullPath);
        if (ret == FALSE)
        {
                //do_rotlog(WORKDAEMON_PRODUCTNAME, 1, LV_INFO, __FILE__, __LINE__, "fail to get config file information...");
        }

       // InitRotLog(IDENT_DEFAULT, szDLogFilePath, get_bytetoMbyte(50), 5, 1);

	if (geteuid() != 0 || getuid() != 0)
        {
		exit(0);
	}
//
//	daemon_init();
//	SetSignal();
//
	already_running(szWorkDaemonPIDFullPath);
/*
        if ((wd_daemon_pid = fork())== 0)
        {
		do_log2(_LOG_INFO, "wd_daemon_pid SUCCESS");
		while (1)
		{
			ret = daemon_monitoring(szConfFileFullPath, szMainDaemonPIDFullPath, szErrMsg ) ;
			sleep(5);
		}
        }

	
	if ((wd_container_pid = fork()) == 0 )
	{
		do_log2(_LOG_INFO, "wd_container_pid SUCCESS");
		while (1)
		{
			ret = container_monitoring();
			sleep(5);
		}
	}
	else
	{
		do_log2(_LOG_INFO, "wd_container_pid FAIL");
	}
*/
	daemon_init();
        SetSignal();

	while (1)
	{

		ret = daemon_monitoring(szConfFileFullPath, szMainDaemonPIDFullPath, szErrMsg ) ;

		ret = container_monitoring();
		
		/*
		ret = rotdconf_read_conf(szConfFileFullPath);
        	if (ret == FALSE )        	{

			printf ("conf read fail...\nn");
                	//ERROR MSG
        	}

		ret = rotdconf_get_conf("MOND_WATCHDOG_ENABLE", szBuffer );
		if (strcmp (szBuffer , "YES") != 0 )
		{
			sleep (5);
			continue;
		}

		memset (szBuffer, 0x00 , sizeof (szBuffer ));
		// first check mond
		ret = rotdconf_get_conf(MON_TARGET_D_LIST_KEY, szBuffer );
		if (ret == FALSE )		{
			//ERROR MSG
			
		}

		if (is_file(szMainDaemonPIDFullPath) == TRUE )
		{
			pid = get_pid(szMainDaemonPIDFullPath);
			if (pid == E_RET )		{
				//ERROR 
				sleep(1);
				continue;
			}
			ret = find_process(pid, MAINDAEMON_PRODUCTNAME);
			if (ret != TRUE )
                        {
				
	                        if (do_cmd_set(MAINDAEMON_PRODUCTNAME, szMainDaemonFullPath) == TRUE )                                  {
        	                        // SUCCESS LOG
					//do_rotlog(WORKDAEMON_PRODUCTNAME, 1, LV_INFO, __FILE__, __LINE__, "target process(daemon) [%s] has been successfully restarted.",MAINDAEMON_PRODUCTNAME);
                                }
			}

		}

		nCount = split (szBuffer, ';', &tarTarName );
		if (tarTarName == NULL )		{
			//ERROR MSG
			continue;
			sleep (1);
		}

		for (i = 0 ; i < nCount ; i ++ )
		{

			char szItem[MAX_FULLPATH_SIZE] = {0}, szTarName[256] = {0}, szPath[MAX_FULLPATH_SIZE] = {0};
			if (tarTarName[i] == NULL || tarTarName[i][0] == 0x00 || strlen (tarTarName[i] ) <= 0 )			{
				sleep (1);
				continue;
			}
			
			memset (szItem, 0x00, sizeof (szItem));
			sprintf (szItem, "%s", tarTarName[i]);
			char * cData = strtok(szItem, "|");
			sprintf (szTarName, "%s", cData);
			cData = strtok(NULL, "|");
			sprintf (szPath, "%s", cData );

			memset (szPIDFileFullPath, 0x00, sizeof (szPIDFileFullPath));
			
			snprintf (szPIDFileFullPath, MAX_FULLPATH_SIZE, "%s/%s.pid", szCheckPIDFilePath, szTarName);
			if (is_file(szPIDFileFullPath) == TRUE)			{

				pid = get_pid(szPIDFileFullPath);
				if (pid == E_RET )
				{
					sleep(2);
					continue;
				}
		
				ret = find_process(pid, szTarName);
				if (ret != TRUE )
				{
					
					if (do_cmd_set(szTarName, szPIDFileFullPath) == TRUE )					{					
						// SUCCESS LOG
						 //do_rotlog(WORKDAEMON_PRODUCTNAME, 1, LV_INFO, __FILE__, __LINE__, "target process(daemon) [%s] has been successfully restarted.",szTarName);
					}

					else
					{
						// FAILLER LOG
					}
				}
			}

			
		}
		*/
		// scend check target daemon list
		
		sleep (5);

	}	

	return 0;
}
