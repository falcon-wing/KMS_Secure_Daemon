#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <fcntl.h>
#include "def.h"

//extern s_token *keyval;
s_token *keyval = NULL;
char *tbuf;
int lines;
static const char data[]="";
//g_szLockFile
extern char g_szLogFilename[MAX_FULLPATH_SIZE + 1];
extern char g_szLockFilename[MAX_FULLPATH_SIZE + 1];
char * get_conf_type_of_string(int _KeyIndex, char * szErrMsg);

unsigned int get_bytetoMbyte(int iMbyte)
{
        return (iMbyte * 1000000);
}

time_t get_ctime(void)
{
        struct timeval tv;
        struct timezone tz;
        int ret;

        ret = gettimeofday(&tv, &tz);
        if (ret == -1)
        {
                return -1L;
        }

        return tv.tv_sec;
}

int time_to_str(time_t tTime, char *szDateTime)
{
        struct tm *ptmTime;

        ptmTime = localtime(&tTime);

        sprintf(szDateTime, "%04d%02d%02d%02d%02d%02d",
                ptmTime->tm_year + 1900, ptmTime->tm_mon + 1, ptmTime->tm_mday,
                ptmTime->tm_hour, ptmTime->tm_min, ptmTime->tm_sec);

        return 0;
}

int rot_unlink(const char *path)
{
        int ret;

        if ((ret = unlink(path)) == -1)
        {
                if (errno == EACCES) 
                {
                        ret = unlink(path);
                }
        }

        return ret;
}

//<ETC>
bool NeedUpdateDate()
{
	 time_t _time;
        struct tm old_tm, *now_tm;
        int nBeforLastDate = 0, nNewLastDate = 0;
        char szErrMsg[1024] = {0};
        char sData[MAX_UNIXTIME_DIGITS + 1] = {0};
        memset (&sData, 0x00 , sizeof (sData));
        sprintf (sData, "%s",get_conf_type_of_string(MOND_INDEX_LOG_LASTDATE,szErrMsg));
        strptime(sData, "%Y-%m-%d", &old_tm);

	_time = time (NULL);
        now_tm = localtime (&_time);
	
	if (old_tm.tm_year < now_tm->tm_year || old_tm.tm_year > now_tm->tm_year)
        {
                return true;
        }
        else
        {
                if (old_tm.tm_mon < now_tm->tm_mon || old_tm.tm_mon > now_tm->tm_mon)
                {
                        return true;
                }

                else
                {
                        if(old_tm.tm_mday < now_tm->tm_mday)
                        {
                                return true;
                        }
                }

        }

	return false;
}

//<FILE>
int set_errno(int err)
{
        errno = err;
        return -1;
}

int s_isreg(unsigned short _st_mode)
{
       if (S_ISREG(_st_mode))
                return TRUE;
        else
                return FALSE;
}

int set_fl(int fd, int flags)
{
    int val;

    if ((val = fcntl(fd, F_GETFL, 0)) < 0)
        return -1;

    val |= flags;

    if (fcntl(fd, F_SETFL, val) < 0)
        return -1;

    return 0;
}

int rot_file_getsize(int fd)
{
    struct stat buf;

    if (fstat(fd, &buf) == 0)
    {
        return buf.st_size;
    }
    else
    {
        return -1;
    }
}

int rot_file_open(const char *path)
{
    return rot_file_open_ex(path, CREATE_MODE);
}

int rot_file_open_ex(const char *path, int mode)
{
    int fd;
    struct stat statbuf;
    int locktype;

    if (path == NULL)
    {
        return -1;
    }

    if (access(path, F_OK) < 0)
    {
        if (mode == O_RDONLY)
        {
            return -1;
        }

        //))
    }

    return 0;
}

int rot_file_open_ex_second(const char *path, int oflag, mode_t mode)
{
    int ret;

    if ((ret = open(path, oflag, mode)) == -1)
    {
        if (errno == EACCES) // SO ±ÇÇÑÀ¸·Î º¯°æ
        {
            ret = open(path, oflag, mode);
        }
    }

    return ret;
}

int rot_file_close(int fd)
{
    int ret = 0;

    return ret;
}

int rot_file_createdir(const char *path)
{
    int ret = 0;
    struct stat st = {0};

    ret = stat(path, &st);
    if (ret == -1)
    {

        ret = mkdir(path, 755);
    }

    return ret;
}

int rot_file_create(const char *path)
{
    int ret = 0;

    return rot_file_create_ex(path, CREATE_MODE);
}

int rot_file_create_ex(const char *path, mode_t mode)
{
    int fd;

    if ((fd = open(path, O_RDWR | O_CREAT | O_TRUNC, mode)) < 0)
    {
        return -1;
    }

    set_fl(fd, O_NONBLOCK);

    return fd;
}

int rot_file_copy(const char *src, const char *dest)
{
    int fd_s, fd_t;
    int isize;
    char *buff = NULL;

    if ((fd_s = rot_file_open_ex(src, O_RDONLY)) < 0)
    {
        return -1;
    }

    if ((fd_t = rot_file_open_ex(dest, O_RDONLY)) < 0)
    {
        rot_file_close(fd_s);
        return -1;
    }

    if ((isize = rot_file_getsize(fd_s)) < 0)
    {
        rot_file_close(fd_s);
        rot_file_close(fd_t);
        return -1;
    }

    if (isize > 0)
    {

        if ((buff = (char *)malloc(isize)) == NULL)
        {
            rot_file_close(fd_s);
            rot_file_close(fd_t);
            return -1;
        }

        if (read(fd_s, buff, isize) != isize)
        {
            rot_file_close(fd_s);
            rot_file_close(fd_t);

            free(buff);
            return -1;
        }

        ftruncate(fd_t, 0);
    }
}

int rot_file_lock(int fd)
{
    if (fchmod(fd, MU_RLOCKMODE) < 0)
    {
        return -1;
    }

    if (write_lock(fd, 0, SEEK_SET, 0) < 0)
    {
        return -1;
    }

    return 0;
}

void rot_file_unlock(int fd)
{
    un_lock(fd, 0, SEEK_SET, 0);
}

void FreeFileLock(int fd)
{
        close(fd);
}

int rot_file_getfilelock(char *szLockFile, mode_t _modeCreate, mode_t _modeOpen)
{
    int fd = 0;

lock_reopen:
    if ((fd = rot_file_open_ex_second(szLockFile, O_CREAT | O_WRONLY, _modeOpen)) == -1)
    {
        if (errno == EAGAIN)
            goto lock_reopen;
        else
            return -1;
    }
relock:
    lseek(fd, 0, SEEK_SET);
    if (lockf(fd, F_TLOCK, 1) == -1) /* lock test */
    {
        if ((errno == EAGAIN) || (errno == EACCES))
            goto relock;
        else
        {
            close(fd);
            return -1;
        }
    }
}

int lock_reg(int fd, int cmd, int type, off_t offset, int whence, off_t len)
{
    struct flock lock;

    lock.l_type = type;
    lock.l_start = offset;
    lock.l_whence = whence;
    lock.l_len = len;

    return (fcntl(fd, cmd, &lock));
}

int rot_file_isfile(char *path)
{
    int ret;
    struct stat st;

    ret = stat(path, &st);
    if (ret < 0)
        return -1;

    if (S_ISREG(st.st_mode))
        return TRUE;
    else
        return FALSE;
}

int rot_file_isdir(char *path)
{
    int ret;
    struct stat st;

    ret = stat(path, &st);
    if (ret < 0)
        return E_RET;

    if (S_ISDIR(st.st_mode))
        return TRUE;
    else
        return FALSE;
}

FILE *rot_file_fopen(const char *filename, const char *mode)
{
    FILE *fp;

    if ((fp = fopen(filename, mode)) == NULL)
    {
        if (errno == EACCES)
        {
            fp = fopen(filename, mode);
        }
    }
    return fp;
}

int is_file(char *path)
{
        int ret;
        struct stat st;

        /* _DEBUGLOG("IS_FILE", LV_DEBUG2, "Check file existance [%s].", path); */
        ret = stat(path, &st);
        if (ret < 0)
                return E_RET;

        return s_isreg(st.st_mode);
}

int is_num(char *arg)
{
        int i;

        if (*arg == 0x00)
                return FALSE;

        for (i=0 ; *(arg+i) != NULLC ; i++)
        {
                if (i == 0)
                {
                        if (!isdigit((int)*arg) && (*arg != '-'))
                                return FALSE;
                }
                else
                {
                        if (!isdigit((int)*(arg+i)))
                                return FALSE;
                }
        }

        return TRUE;
}


//<PROCESS>
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
                return FALSE;
        }
        pclose(fp);

        return TRUE;
}

//<>
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
                        /* counting white space */
                        if (flag == 2)
                        {
                                *buf = 0x00;
                                flag = 0;
                                break;
                        }
                }
                else
                {
                        /* counting alpha-numeric character */
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

char *rot_getcwd()
{
        char *strCurPath = malloc(MAX_FULLPATH_SIZE);
        getcwd(strCurPath, MAX_FULLPATH_SIZE);

        return strCurPath;
}

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

void daemonization()
{

	pid_t pid;

        /* Fork off the parent process */
        pid = fork();

        /* An error occurred */
        if (pid < 0)
                exit(EXIT_FAILURE);

        /* Success: Let the parent terminate */
        if (pid > 0)
                exit(EXIT_SUCCESS);

        /* On success: The child process becomes session leader */
        if (setsid() < 0)
                exit(EXIT_FAILURE);

        /* Catch, ignore and handle signals */
        // TODO: Implement a working signal handler */
        signal(SIGCHLD, SIG_IGN);
        signal(SIGHUP, SIG_IGN);

        struct sigaction sa;
        sa.sa_handler = SIG_IGN;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        sigaction(SIGPIPE, &sa, NULL);

        /* Fork off for the second time*/
        pid = fork();

        /* An error occurred */
        if (pid < 0)
                exit(EXIT_FAILURE);

	/* Success: Let the parent terminate */
        if (pid > 0)
                exit(EXIT_SUCCESS);

        /* Set new file permissions */
        umask(0);

        /* Change the working directory to the root directory */
        /* or another appropriated directory */
        chdir("/");
        /* Close all open file descriptors */
        int x;
        for (x = sysconf(_SC_OPEN_MAX); x >= 0; x--)
        {
                close(x);
        }
}



void SetSignal(){
        struct sigaction sa;

        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        sa.sa_handler = SIG_DFL;

        sigaction(SIGTERM, &sa, NULL);
        sigaction(SIGHUP, &sa, NULL);
        sigaction(SIGCHLD, &sa, NULL);
        sigaction(SIGINT, &sa, NULL);
        sigaction(SIGPIPE, &sa, NULL);
}


//<JSON>
json_object *get_cmd_at_jsondata(json_object *jsRootData)
{
    return json_object_object_get(jsRootData, JSON_KEYNM_CMD);
}

json_object *get_targeturl_at_jsondata(json_object *jsTargetObj)
{
    return json_object_object_get(jsTargetObj, JSON_KEYNM_URL);
}

json_object *get_trid_at_jsondata(json_object *jsHeaderObj)
{
    return json_object_object_get(jsHeaderObj, JSON_KEYNM_TRID);
}

json_object *get_function_at_jsondata(json_object *jsHeaderObj)
{
    return json_object_object_get(jsHeaderObj, JSON_KEYNM_FUNC);
}

json_object *get_bodydata_at_jsondata(json_object *jsBodyObj)
{
    return json_object_object_get(jsBodyObj, JSON_KEYNM_DATA);
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
   // json_object_object_add(jsMainObj, JSON_KEYNM_CMD, json_object_new_string(_sCmd));
    //json_object *jsReqObj = json_object_new_object();
    //json_object *jstargetObj = json_object_new_object();
    json_object *jsheaderObj = json_object_new_object();
    json_object *jsbodyObj = json_object_new_object();

/*
    json_object_object_add(jstargetObj, JSON_KEYNM_URL, json_object_new_string(_sUrl));
    json_object_object_add(jsheaderObj, JSON_KEYNM_TRID, json_object_new_string(_sTrid));
    json_object_object_add(jsheaderObj, JSON_KEYNM_FUNC, json_object_new_string(_sfunc));
*/
    json_object_object_add(jsheaderObj, JSON_KEYNM_TRID, json_object_new_string(_sTrid));
    json_object_object_add(jsheaderObj, JSON_KEYNM_RTNCODE, json_object_new_string(retCode));
    json_object_object_add(jsheaderObj, JSON_KEYNM_RTNMESSAGE, json_object_new_string(_retMessage));

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

    //json_object_object_add(jsReqObj, JSON_SUBOBJNAME_TAR, jstargetObj);
    //json_object_object_add(jsReqObj, JSON_SUBOBJNAME_HEADER, jsheaderObj);
    //json_object_object_add(jsReqObj, JSON_SUBOBJNAME_BODY, jsbodyObj);
    //json_object_object_add(jsMainObj, JSON_SUBOBJNAME_REQ, jsReqObj);

    json_object_object_add(jsMainObj, JSON_SUBOBJNAME_HEADER, jsheaderObj);
    json_object_object_add(jsMainObj, JSON_SUBOBJNAME_BODY, jsbodyObj);

    snprintf(strRespJson, MAX_HADERDATA_SIZE + MAX_BYDY_LEN, "%s", json_object_get_string(jsMainObj));

   /* if (jstargetObj != NULL)
    {
    //    json_object_object_del(jstargetObj, JSON_SUBOBJNAME_TAR);
    }
*/
    if (jsheaderObj != NULL)
    {
        json_object_object_del(jsheaderObj, JSON_SUBOBJNAME_HEADER);
    }

    if (jsbodyObj != NULL)
    {
        json_object_object_del(jsbodyObj, JSON_SUBOBJNAME_BODY);
    }
   
  /*  nCnt = json_object_object_length(jsReqObj);
    if (nCnt == 0 && jsReqObj != NULL)
    {
        json_object_object_del(jsReqObj, JSON_SUBOBJNAME_REQ);
    }
*/
    return strRespJson;
}

	

//<STRING>

int pars_key_n_value(char *_sData, char *_ckey, char *_cvalue)
{
    _ckey = strtok(_sData, "|");
    _cvalue = strtok(NULL, "|");
    return TRUE;
}

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

//<CONTAINER WORKING>

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


//<CONFIG>
int rotdconf_file_lines(FILE *fp)
{
    char rbuf[L_LINEBUF];
    int line = 0;

    while (fgets(rbuf, L_LINEBUF, fp))
    {
        rbuf[L_LINEBUF - 1] = 0x00;
        if ((*rbuf == '#') || (*rbuf == '\n'))
            continue;

        line++;
    }

    return line;
}

char *rotdconf_token(char *buf)
{
    int flag = 1;
    char *tp;

    if (buf == NULL)
    {
        if (tbuf == NULL)
        {
            return NULL;
        }
        else
            buf = tbuf;
    }

    while (*buf)
    {
        if (isspace((int)*buf) || (*buf == '='))
        {
            /* counting white space */
            if (flag == 2)
            {
                tbuf = buf;
                *tbuf++;
                *buf = '\0';
                flag = 0;
                break;
            }
        }
        else
        {
            if (flag == 1)
            {
                /* remark character '#' is found at the first line */
                if (*buf == '#')
                    break;
                else
                {
                    tp = buf;
                    flag = 2;
                }
            }

            if (*buf == '#')
            {
                tbuf = buf;
                *tbuf++;
                *buf = '\0';
		flag = 0;
                break;
            }
        }

        *buf++;
    }

    if (flag != 1)
    {
        if (strlen(tp) > L_TOKEN - 1)
            *(tp + L_TOKEN - 1) = 0x00;
        return tp;
    }

    return NULL;
}


int rotdconf_read_conf(char *path)
{
    FILE *fp;
    int i = 0;
    char *tok;
    char rbuf[L_LINEBUF];

    fp = fopen(path, "r");
    if (fp == NULL)
    {
        return FALSE;
    }

    lines = rotdconf_file_lines(fp);
    if (lines == 0)
    {
        fclose(fp);
        return FALSE;
    }

    /* allocating memory */
    keyval = (s_token *)malloc(sizeof(s_token) * (lines + 1));
    if (keyval == NULL)
    {
        fclose(fp);
        return FALSE;
    }

    if (fseek(fp, 0, SEEK_SET))
    {
        fclose(fp);
        return FALSE;
    }

    while (fgets(rbuf, L_LINEBUF, fp))
    {
        rbuf[L_LINEBUF - 1] = 0x00;
        if ((*rbuf == '#') || (*rbuf == '\n'))
            continue;

        tok = rotdconf_token(rbuf);
        if (tok != NULL)
        {
            strncpy(keyval[i].keywd, tok, L_KEYWD - 1);
            keyval[i].keywd[L_KEYWD - 1] = 0x00;
        }
        else
		continue;

        tok = rotdconf_token(NULL);
        if (tok != NULL)
        {
            strncpy(keyval[i].value, tok, L_TOKEN - 1);
            keyval[i].value[L_TOKEN - 1] = 0x00;
        }
        else
            keyval[i].value[0] = 0x00;

        if (keyval[i].keywd != NULL)
            i++;

        if (i > lines)
        {
            fclose(fp);
            return FALSE;
        }
    }

    lines = i;
    fclose(fp);
    return TRUE;
}

int rotdconf_get_conf(const char *key, char *keybuf)
{
    int i;

    for (i = 0; i < lines; i++)
    {
        /* found it! */
        /* Compare two keywords with insensitive character */
        if (!strcasecmp(keyval[i].keywd, key))
        {
            strncpy(keybuf, keyval[i].value, L_TOKEN - 1);
            keybuf[L_TOKEN - 1] = 0x00;
            return TRUE;
        }
    }

    /* not found! */
    *keybuf = 0x00;

    return FALSE;
}

int rotdconf_close_conf(void)
{
    if (keyval != NULL)
        free(keyval);
    keyval = NULL;

    return TRUE;
}

int get_monD_conf(monDLogconf_t * _Dconf, char * szErrMsg )
{
	int ret = 0;
	char szConfFilePath[MAX_FULLPATH_SIZE] = {0};
	char szLineBuf[1024] = {0};
	char *strCurrPath = NULL;

	memset (&szLineBuf, 0x00 , sizeof (szLineBuf));
	memset(&szConfFilePath, 0x00, sizeof(szConfFilePath));
	snprintf(szConfFilePath, MAX_FULLPATH_SIZE, "%s/%s/%s", ROOT_PATH, ROT_CONF, ROT_DCONFILE);
	memset (_Dconf, 0x00 , sizeof ( monDLogconf_t));

	if (rot_file_isfile(szConfFilePath) == FALSE)
	{
		//do_rotlog(MAINDAEMON_PRODUCTNAME, 1, LV_INFO,__FILE__, __LINE__, "[get_rotD_conf] config file is not found...[%s]", szConfFilePath);
		// ERROR MSG
		return 0;
	}

	ret = rotdconf_read_conf( szConfFilePath);
	if (ret == FALSE)
	{
		//do_rotlog(MAINDAEMON_PRODUCTNAME, 1, LV_INFO,__FILE__, __LINE__, "[get_rotD_conf] fail to read config .[%s]", szConfFilePath);
		return 0;
	}

	ret = rotdconf_get_conf(MOND_DIR_LOG, szLineBuf);
	if (ret == TRUE)
	{
		snprintf (_Dconf->szLogFolderNm, MAX_FULLPATH_SIZE, "%s", szLineBuf);
	}
	else
	{
		// you have to set default rule
	}

	ret = rotdconf_get_conf(MOND_BACKDIR_LOG, szLineBuf);
	if (ret == TRUE)
	{
		snprintf (_Dconf->szBackLogFolderNm, MAX_FULLPATH_SIZE, "%s", szLineBuf);
	}

	else
	{
		// you have to set default rule
	}

	ret = rotdconf_get_conf(MOND_ROTSIZE_LOGFILE, szLineBuf);
	if (ret == TRUE)
	{
		_Dconf->nLogFileSize = atoi(szLineBuf);
	}
	else
	{
		// you have to set default rule
		_Dconf->nLogFileSize = 5;
	}

	ret = rotdconf_get_conf(MOND_ROTCNT_LOGFILE, szLineBuf);
	if (ret == TRUE)
	{
		_Dconf->nLogFileCnt = atoi(szLineBuf);
	}
	else
	{
		// you have to set default rule
		_Dconf->nLogFileCnt = 5;
	}

	ret = rotdconf_get_conf(MOND_ROTATE_ENABLE, szLineBuf);
	if (ret == TRUE)
	{
		_Dconf->cRotateEnable = szLineBuf[0];
	}
	else
	{
		// you have to set default rule
		_Dconf->cRotateEnable = 'N';
	}

	ret = rotdconf_get_conf(MOND_WATCHDOG_ENABLE, szLineBuf);
	if (ret == TRUE )
	{
		_Dconf->cWatchDogEnable = szLineBuf[0];
	}
	else
	{
		_Dconf->cWatchDogEnable = 'N';
	}

	ret = rotdconf_get_conf(MOND_TARGET_CONTAINER, szLineBuf );
	if (ret == TRUE)
	{
		sprintf (_Dconf->szTargetContainer, "%s", szLineBuf);
	}
	else
	{
		sprintf ( _Dconf->szTargetContainer, "");
	}

	ret = rotdconf_get_conf(MOND_TARGET_DAEMON, szLineBuf );
	if (ret == TRUE)
	{
		sprintf (_Dconf->szTargetDaemon, "%s", szLineBuf);
	}
	else
	{
		 sprintf (_Dconf->szTargetDaemon, "");
	}

	memset (szLineBuf, 0x00 , sizeof (szLineBuf));
	ret = rotdconf_get_conf(MOND_DOCKER_URL, szLineBuf );
	if (ret == TRUE)
	{
		sprintf (_Dconf->szDockerUrl, "%s", szLineBuf);
	}
	else
	{
		sprintf (_Dconf->szDockerUrl, "");
	}
	
	memset (szLineBuf, 0x00 , sizeof (szLineBuf));
	ret = rotdconf_get_conf(MOND_LOG_LASTDATE, szLineBuf);
	if (ret == TRUE )
	{
		sprintf (_Dconf->szLogLastDate, "%s", szLineBuf);
	}
	else
	{
		sprintf (_Dconf->szLogLastDate, "");
	}

	rotdconf_close_conf();
	return TRUE;
}	

char * get_conf_type_of_string(int _KeyIndex, char * szErrMsg)
{
        int ret = 0;
        BOOL bRet = FALSE;
        monDLogconf_t conf;
        char szData[1024] = {0};
        char * szRetData = NULL;
        memset (&conf, 0x00 , sizeof (conf ));

        bRet = get_monD_conf(&conf, szErrMsg );
        if (bRet == FALSE )
        {
                return NULL;
        }

        switch (_KeyIndex )
        {
                case MOND_INDEX_DIR_LOG:
                        szRetData = (char *) malloc (strlen (conf.szLogFolderNm));
                        sprintf (szRetData, "%s", conf.szLogFolderNm);
                break;
                case MOND_INDEX_BACKDIR_LOG:
                        szRetData =  (char *) malloc (strlen (conf.szBackLogFolderNm));
                        sprintf (szRetData, "%s", conf.szBackLogFolderNm);
                break;
                case MOND_INDEX_ROTSIZE_LOGFILE:
                        sprintf (szData, "%d", conf.nLogFileSize);
                        szRetData = (char*) malloc (strlen(szData));
                        sprintf (szRetData, "%s", szData);
                break;
                case MOND_INDEX_ROTCNT_LOGFILE:
                        sprintf (szData, "%d", conf.nLogFileCnt);
                        szRetData = (char *) malloc (strlen(szData));
		break;
                case MOND_INDEX_ROTATE_ENABLE:
                        if (conf.cRotateEnable == 'Y')
                        {
                                sprintf (szData, "%s", FUNC_ENABLE);
                        }
                        else
                        {
                                sprintf (szData, "%s", FUNC_DESABLE);
                        }
                        szRetData = (char *) malloc (strlen(szData));
                        sprintf (szRetData, "%s", szData);

                break;
                case MOND_INDEX_WATCHDOGENABLE:
                        if (conf.cWatchDogEnable == 'Y')
                        {
                                sprintf (szData, "%s", FUNC_ENABLE);
                        }
                        else
                        {
                                sprintf (szData, "%s", FUNC_DESABLE);
                        }
                        szRetData = (char *) malloc (strlen(szData));
                        sprintf (szRetData, "%s", szData);
                break;
                case MOND_INDEX_TAR_CONTAINER:
                        szRetData = (char *) malloc (strlen (conf.szTargetContainer));
                        sprintf (szRetData , "%s", conf.szTargetContainer);
                break;
                case MOND_INDEX_TAR_DAEMON:
                        szRetData = (char *) malloc (strlen (conf.szTargetDaemon));
                        sprintf (szRetData, "%s", conf. szTargetDaemon);
                break;
		case MOND_INDEX_DOCKER_URL:
                        szRetData = (char *) malloc (strlen (conf.szDockerUrl));
                        sprintf (szRetData , "%s", conf.szDockerUrl);
                break;
                case MOND_INDEX_LOG_LASTDATE:
                        szRetData = (char *) malloc (strlen (conf.szLogLastDate));
                        sprintf (szRetData, "%s", conf.szLogLastDate);
                break;
                default:
                        return NULL;
                break;
        }

        return szRetData;
}


int set_monD_conf(monDLogconf_t * _Dconf, char * szErrMsg )
{
    int ret = 0;
    FILE * fp = NULL;
    char szConfFilePath[MAX_FULLPATH_SIZE] = {0};
    char szConfFileTmpPath[MAX_FULLPATH_SIZE] = {0};
    char szConfFileOldPath[MAX_FULLPATH_SIZE] = {0};

    char szLineBuf[1024] = {0};
    snprintf(szConfFilePath, MAX_FULLPATH_SIZE, "%s/%s/%s", /*g_strRot_D_RootPath*/ROOT_PATH, ROT_CONF, ROT_DCONFILE);
    if (rot_file_isfile(szConfFilePath) == FALSE)
    {
        rot_file_create(szConfFilePath);
    }

    snprintf(szConfFileOldPath, MAX_FULLPATH_SIZE, "%s.old", szConfFilePath);
    snprintf(szConfFileTmpPath, MAX_FULLPATH_SIZE, "%s.tmp", szConfFilePath);
    fp = fopen(szConfFileTmpPath, "w");
    if (fp == NULL)
    {
        /// ERROR MESSAGE
        return FALSE;
    }
    snprintf (szLineBuf, MAX_FULLPATH_SIZE, "%s = %s\n", MOND_DIR_LOG, _Dconf->szLogFolderNm);
    fputs(szLineBuf, fp);

    memset (szLineBuf, 0x00 , sizeof (szLineBuf));
    snprintf (szLineBuf, MAX_FULLPATH_SIZE, "%s = %s\n", MOND_BACKDIR_LOG, _Dconf->szBackLogFolderNm);
    fprintf (fp, "%s" , szLineBuf);

    memset (szLineBuf, 0x00 , sizeof (szLineBuf));
    snprintf (szLineBuf, MAX_FULLPATH_SIZE, "%s = %d\n", MOND_ROTSIZE_LOGFILE, _Dconf->nLogFileSize);
    fprintf (fp, "%s" , szLineBuf);

    memset (szLineBuf, 0x00 , sizeof (szLineBuf));
    snprintf (szLineBuf, MAX_FULLPATH_SIZE, "%s = %d\n", MOND_ROTCNT_LOGFILE, _Dconf->nLogFileCnt);
    fprintf (fp, "%s" , szLineBuf);

    memset (szLineBuf, 0x00 , sizeof (szLineBuf));

    snprintf (szLineBuf, MAX_FULLPATH_SIZE, "%s = %c\n", MOND_ROTATE_ENABLE, _Dconf->cRotateEnable);
    fprintf (fp, "%s" , szLineBuf);

    memset (szLineBuf, 0x00, sizeof (szLineBuf));
    snprintf (szLineBuf, MAX_FULLPATH_SIZE, "%s = %c\n", MOND_WATCHDOG_ENABLE, _Dconf->cWatchDogEnable);
    fprintf (fp, "%s" , szLineBuf);

    memset (szLineBuf, 0x00, sizeof (szLineBuf));
    snprintf (szLineBuf, MAX_FULLPATH_SIZE, "%s = %s\n", MOND_TARGET_CONTAINER, _Dconf->szTargetContainer);
    fprintf (fp, "%s" , szLineBuf);

    memset (szLineBuf, 0x00, sizeof (szLineBuf));
    snprintf (szLineBuf, MAX_FULLPATH_SIZE, "%s = %s\n", MOND_TARGET_DAEMON, _Dconf->szTargetDaemon);
    fprintf (fp, "%s" , szLineBuf);

    memset (szLineBuf, 0x00 , sizeof (szLineBuf));
    snprintf (szLineBuf , MAX_FULLPATH_SIZE, "%s = %s\n", MOND_DOCKER_URL, _Dconf->szDockerUrl);
    fprintf (fp, "%s", szLineBuf);

    memset (szLineBuf, 0x00, sizeof (szLineBuf));
    snprintf (szLineBuf, MAX_FULLPATH_SIZE, "%s = %s\n", MOND_LOG_LASTDATE, _Dconf->szLogLastDate);
    fprintf (fp, "%s", szLineBuf);

    rename(szConfFilePath, szConfFileOldPath);
    ret = rename(szConfFileTmpPath, szConfFilePath);

    if( ret != 0)
    {
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return TRUE;
}


int set_conf_type_of_string(int _KeyIndex, char * _data, char * szErrMsg)
{
        int ret = 0;
        BOOL bRet = FALSE;
        monDLogconf_t conf;
        memset (&conf, 0x00 , sizeof (conf ));

        bRet = get_monD_conf(&conf, szErrMsg );

        switch (_KeyIndex )
        {
                case MOND_INDEX_DIR_LOG:
                        sprintf (conf.szLogFolderNm, "%s", _data);
                break;
                case MOND_INDEX_BACKDIR_LOG:
                        sprintf (conf.szBackLogFolderNm, "%s", _data);
                break;
                case MOND_INDEX_ROTSIZE_LOGFILE:
                        conf.nLogFileSize = atoi(_data);
                break;
                case MOND_INDEX_ROTCNT_LOGFILE:
                        conf.nLogFileCnt =atoi( _data);
                break;
                case MOND_INDEX_ROTATE_ENABLE:
                        if (strcmp (FUNC_ENABLE, _data ) == 0 )
                        {
                                conf.cRotateEnable = 'Y';
                        }
                        else
                        {
                                conf.cRotateEnable = 'N';
                        }
                break;
		case MOND_INDEX_WATCHDOGENABLE:
                        if (strcmp (FUNC_ENABLE, _data ) == 0 )
                        {
                                conf.cWatchDogEnable = 'Y';
                        }
                        else
                        {
                                conf.cWatchDogEnable = 'N';
                        }
                break;
                case MOND_INDEX_TAR_CONTAINER:
                        sprintf (conf.szTargetContainer, "%s", _data);
                break;
                case MOND_INDEX_TAR_DAEMON:
                        sprintf (conf.szTargetDaemon, "%s", _data);
                break;
                case MOND_INDEX_DOCKER_URL:
                        sprintf (conf.szDockerUrl, "%s", _data );
                break;
                case MOND_INDEX_LOG_LASTDATE:
                        sprintf (conf.szLogLastDate, "%s", _data);
                break;
                default:
                break;
        }

	bRet = set_monD_conf(&conf, szErrMsg );
        if (bRet == TRUE)
        {
                bRet = 1;
        }

        return ret;
}

int get_filelock(void)
{
	int ret;
        int fd = -1;
        int nCount = 0;

lock_reopen :
        if ( (fd = open(g_szLockFilename, O_CREAT|O_WRONLY, LOCK_FILEMODE)) == -1 )
        {

                if ( errno == EAGAIN || errno == EACCES )       /* AIX=EACCESS, SOLARIS=EAGAIN, HPUX=both */ /* log file is locked */
                {
                        /* Check Role State - If not SO process, set SO process itself */

                        nCount++;
                        if (nCount == 3)
                                return -1;

                        goto lock_reopen;
                }
                else
                        return -1;
        }

relock :
	lseek(fd, 0, SEEK_SET);
        if ( lockf(fd, F_TLOCK, 1) == -1 )  /*lock test */
        {
                if ( errno == EAGAIN || errno == EACCES )       /* AIX=EACCESS, SOLARIS=EAGAIN, HPUX=both */
                {
                        /* Check Role State - If not SO process, set SO process itself */

                        nCount++;
                        if (nCount == 3)
                                return -1;

                        goto relock;
                }
                else
                {
                        close(fd);
                        return -1;
                }
        }


        return fd;
}

void free_filelock(int fd)
{
	int ret;
refree:
        ret = close(fd);
        if (ret == -1)
        {
                if (errno == EINTR)
                        goto refree;
        }

}
