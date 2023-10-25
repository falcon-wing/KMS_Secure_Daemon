#include <stdlib.h>
#include <strings.h>
#include <time.h>
#include <string.h>

#include <sys/procfs.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/procfs.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include "monM_def.h"
#include "utils_str.h"

char *g_strRot_D_RootPath = (char *)NULL;
s_token *keyval = NULL;


#define STR_MAX		256
#define UTIL_MAX	16384

#define TICKS		sysconf(_SC_CLK_TCK)
#define PAGESIZE	sysconf(_SC_PAGESIZE)

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

char *rot_getcwd()
{
        char *strCurPath = malloc(MAX_FULLPATH_SIZE);
        getcwd(strCurPath, MAX_FULLPATH_SIZE);

        return strCurPath;
}

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
                //_DEBUGLOG("GET_TIME", LV_DEBUG, "Gettimeofday : %s", get_strErrMsg(errno));
                return -1L;
        }

        return tv.tv_sec;
}

int rot_unlink(const char *path)
{
        int ret;

        if ((ret = unlink(path)) == -1)
        {
                if (errno == EACCES) // SO ±ÇÇÑÀ¸·Î º¯°æ
                {
                        //     SetSOProc("_set_");

                        ret = unlink(path);
                }
        }

        return ret;
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
/*
char * get_ipadddr_for_socket(SOCKET sockfd)
{
	char * ipaddr;
	int size;
	struct sockaddr_in sockAddr;

	size = sizeof(sockAddr);
	memset(&sockAddr, 0x00, sizeof(sockAddr));

	getpeername(sockfd, (struct sockaddr *) &sockAddr, &size);
 
	char szip[16]={0};
 
	strcpy(szIp, inet_ntoa(sockAddr));
	ipaddr = (char*) malloc (16);
	strcpy (ipaddr, szIp);

	return ipaddr;
}
*/
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

int do_cmd_setV2(char * szCmd, char *szCmdFullPath)
{
	
	char **new_argv;
    	char command[]  = {0};
	char szShellPath[MAX_FULLPATH_SIZE] ={0};
	sprintf (command, "%s",szCmd);
    	int  idx, argc = 1;
	int p_stat, i, ret, slot;
	pid_t pid;
	FILE *pipe;
	new_argv = (char **)malloc(sizeof(char *) * (argc + 1));
	new_argv[0] = command;

	new_argv[1] = NULL;

	pid = fork();
        if (pid < 0)
        {
                free(new_argv);
                //exit (0);
		return E_RET;
        }

	if (pid == 0)
        {
		//chdir("/usr/local/ictk");
		sprintf (szShellPath, "./%s", command);
		if ( 0 != access (szCmdFullPath, F_OK));
		{
			//do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, "Cant't access target[%s] file.(%d)", szCmdFullPath, errno);
			//return E_RET;
		}

		chdir("/usr/local/ictk");

		pipe = popen(szShellPath, "r");
		if (pipe == NULL)
		{
			do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "Target [%s] cannot be executed..[%d]", command, errno);
                        exit (errno);
		}
		
                exit(0);
        }
	else
        {
                waitpid(pid, &p_stat, 0);
                free(new_argv);

                if (WIFEXITED(p_stat))
                {
                        if (WEXITSTATUS(p_stat)==0)
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
        return TRUE;
}


int do_cmd_set(char *szCmd)
{
        char seps = ' ';
        char *token;
        char **args;
        int p_stat, i, ret, slot;
        char cmd[MAX_FULLPATH_SIZE+1];
        pid_t pid;

        strncpy(cmd, szCmd, MAX_FULLPATH_SIZE+1);

        i=0;

        args = (char **)malloc(sizeof(char *)*MAX_ARG_NUM);

        //slot = get_tokslot();
	slot = rot_str_gettokslot();
        if (slot == -1)
        {
                free(args);
                return FALSE;
        }


        //token = xstrtok(cmd, seps, slot);
	token = rot_str_xstrtok(cmd, seps, slot);
        while( token != NULL )
        {
                /* Remove Quotation Mark in Token */
                if (*token == '\"')
                {
                        *token++;
                        ret = strlen(token);
                        if (*(token+ret-1) == '\"')
                                *(token+ret-1) = 0x00;
                }
                args[i] = token;
                i++;

                //token = xstrtok(NULL, seps, slot);
		token = rot_str_xstrtok(NULL, seps, slot);
        }

        args[i] = token;
	rot_str_returntokslot(slot);

        pid = fork();
        if (pid < 0)
        {
                free(args);
                return E_RET;
        }
		
		/* clild process */
        if (pid == 0)
        {
                ret = execv(args[0], args);
                if (ret < 0)
                {
                        exit (errno);
                }
                exit(0);
        }
        /* parent process */
        else
        {
                waitpid(pid, &p_stat, 0);
                free(args);

                if (WIFEXITED(p_stat))
                {
                        if (WEXITSTATUS(p_stat)==0)
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
        return TRUE;
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
/*
struct tm * get_lasttime(int nLastTime)
{
        time_t _time;
        _time = mktime(nLastTime);//nLastTime;

        return localtime(&_time);
}
*/
struct tm * get_nowtime()
{
        time_t _time;
        _time = time(NULL);

        return localtime(&_time);
}

bool NeedUpdateDate(/*char * szData*/ )
{
	time_t _time;
	struct tm old_tm, *now_tm;
        int nBeforLastDate = 0, nNewLastDate = 0;
        char szErrMsg[1024] = {0};
        char sData[MAX_UNIXTIME_DIGITS + 1] = {0};
        memset (&sData, 0x00 , sizeof (sData));
        sprintf (sData, "%s",get_conf_type_of_string(MOND_INDEX_LOG_LASTDATE,szErrMsg));	

	//do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "NeedUpdateDate sData is [%s]...", sData);
	strptime(sData, "%Y-%m-%d", &old_tm);
	
	_time = time (NULL);
	now_tm = localtime (&_time);

	//do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "NeedUpdateDate tm data [%d/%d, %d/%d, %d/%d]...", old_tm.tm_year,now_tm->tm_year,old_tm.tm_mon,now_tm->tm_mon,old_tm.tm_mday,now_tm->tm_mday);

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
	

   /*     nBeforLastDate = atoi(sData);
	do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "-----01");
        struct tm * lasttime = get_lasttime(nBeforLastDate);
	do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "-----02");
        struct tm * nowtime = get_nowtime();
	do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "-----03");

	int nLast = 0, nNew = 0;
	nLast = lasttime->tm_mday;
	nNew = nowtime->tm_mday;

	do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "lasttime->tm_mday [%d]/ nowtime->tm_mday [%d]",nLast, nNew);
        if (((int)lasttime->tm_mday) < ((int) nowtime->tm_mday))
        {
                return true;
        }
*/
        return false;
}
