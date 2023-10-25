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
#include <sys/prctl.h>
#include "rot_command.h"
#include "monM_def.h"
#include <stdbool.h>
#include "rot_sock.h"
#include "mon_log.h"
#include "mon_log2.h"
#include "rot_utils.h"
#include "utils_file.h"


#ifndef SERVER_PORT
#define SERVER_PORT 5001
#endif 

#define LOCKMODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

char g_szRootPath[MAX_FULLPATH_SIZE + 1] = {0};
char *g_pcSERVER_ADDR = (char *)NULL;
BOOL g_nInitSecureLog = FALSE;
char g_szLogFilename[MAX_FULLPATH_SIZE + 1] = {0};
char g_szLockFilename[MAX_FULLPATH_SIZE + 1] = "\0";

char g_szDbLogFilename[MAX_FULLPATH_SIZE + 1] = {0};
char g_szDbLogFileLockFilename[MAX_FULLPATH_SIZE + 1] = {0};

int g_nMaxLogSize = 0;
int g_nMaxLogFileCount = 0;
int g_nRCLogRotate = 0;
char g_szIdent[MAX_LOG_IDENT_SIZE + 1] = "\0";

struct sockaddr_in g_stServ_addr, g_stCli_addr;

static void rot_daemon()
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

        /* Open the log file */
        openlog("firstdaemon", LOG_PID, LOG_DAEMON);
}

void sig_term(int sig){
      //  g_nShutdown = 1;
}

void sig_hup(int sig){
      // g_nReConfig = 1;
}

void SetSignal(){
        struct sigaction sa;

        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
/*
        sa.sa_handler = sig_term;
        sigaction(SIGTERM, &sa, NULL);

        sa.sa_handler = sig_hup;
        sigaction(SIGHUP, &sa, NULL);

        sa.sa_handler = SIG_IGN;
        sigaction(SIGINT, &sa, NULL);
*/
	sa.sa_handler = SIG_DFL;

    	sigaction(SIGTERM, &sa, NULL);
    	sigaction(SIGHUP, &sa, NULL);
    	sigaction(SIGCHLD, &sa, NULL);
    	sigaction(SIGINT, &sa, NULL);
    	sigaction(SIGPIPE, &sa, NULL);
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
	

int main(int argc, char **argv)
{
	pid_t pid, con_watchdog_pid, pid_watchdog_pid, wd_daemon_pid;
	int ret = 0, opt = 1, cli_len = 0, fd, sockclient_pid = 0, nPid;
	//char szDLogFilePath[1024] = {0};
	FILE * fp = NULL;
	struct stat st = {0};
        struct SOCKET_INFO _sockfd, _new_sockfd;
        LPSOCKETINFO sockfd = &_sockfd;
        LPSOCKETINFO new_sockfd = &_new_sockfd;

	struct sockaddr_in sin, cli;
        int sd, ns, clientlen = sizeof(cli), forkret;

	char szDRotPath[MAX_FULLPATH_SIZE] = {0}, szDConfDir[MAX_FULLPATH_SIZE] = {0}, szDLogDir[NAME_MAX] = {0}, szPidPath[MAX_FULLPATH_SIZE] = {0};
        char szDConfFilePath[MAX_FULLPATH_SIZE] = {0}, szDLogFilePath[MAX_FULLPATH_SIZE] = {0}, szLockPidFilePath[MAX_FULLPATH_SIZE] = {0};
	char szWdpidFilePath[MAX_FULLPATH_SIZE] = {0}, szWdFilePath[MAX_FULLPATH_SIZE] = {0};
        char *strCurrPath = NULL;
        strCurrPath = rot_getcwd();

	snprintf (g_szRootPath, MAX_FULLPATH_SIZE - 1, "%s", strCurrPath);
	snprintf(szDRotPath, MAX_FULLPATH_SIZE - 1, "%s", strCurrPath);
        snprintf(szDConfDir, MAX_FULLPATH_SIZE - 1, "%s/%s", strCurrPath, ROT_CONF);
        snprintf(szDLogDir, NAME_MAX - 1, "%s/%s", strCurrPath, ROT_LOGDIR);
        snprintf(szDConfFilePath, MAX_FULLPATH_SIZE, "%s/%s", szDConfDir, ROT_DCONFILE);
        snprintf(szDLogFilePath, MAX_FULLPATH_SIZE, "%s/%s", szDLogDir, ROT_LOGFILE3);
        snprintf(szLockPidFilePath, MAX_FULLPATH_SIZE - 1, "%s/%s", strCurrPath, ROT_DLOCKPIDFILE);
	snprintf(szPidPath, MAX_FULLPATH_SIZE - 1, "%s/etc/%s.pid", strCurrPath,"rotD");

	snprintf(szWdpidFilePath, MAX_FULLPATH_SIZE -1 , "%s/%s/%s.pid", strCurrPath,ETC_DIR,MAINDAEMON_PRODUCTNAME);
	snprintf(szWdFilePath, MAX_FULLPATH_SIZE - 1, "%s/%s", ROOT_PATH,MAINDAEMON_PRODUCTNAME);
	
	umask(022);
	InitRotLog(IDENT_DEFAULT, szDLogFilePath, get_bytetoMbyte(50), 5, 1);

	rot_daemon();
	SetSignal();
	already_running(szWdpidFilePath);

	init_socket(sockfd, SOCK_TEXT_MODE);
	if ((ret = rot_socket(sockfd, AF_INET, SOCK_STREAM, 0)) == -1)
        {

                do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "fail to create socket...");
                exit(0);
        }

	opt = 1;
	
	if ((setsockopt(sockfd->iSocket, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt))) == -1)
        {
                do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "fail to setsockopt...(errno: %d)", errno);
                exit(0);
        }
	
        g_stServ_addr.sin_family = AF_INET;
        g_stServ_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        g_stServ_addr.sin_port = htons(SERVER_PORT);
	do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO,__FILE__, __LINE__, "daemon start...(%d)",SERVER_PORT);
	if (bind(sockfd->iSocket, (struct sockaddr *)&g_stServ_addr, sizeof(g_stServ_addr)) == -1)
        {
		do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "fail to bind server socket.(errno: %d)", errno);
                exit(0);
	}

	if (rot_listen(sockfd, MAX_Q_SIZE) == -1)
        {
                do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "serveer socket listen error...(errno: %d)", errno);
                exit(0);
        }	

	while (1)
	{
		if ((new_sockfd->iSocket = accept(sockfd->iSocket, (struct sockaddr *)&g_stCli_addr, &cli_len)) == INVALID_SOCKET)
                {
			do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO,__FILE__, __LINE__, "accept error");
                        exit(1);
                }
		sockclient_pid = fork();
		if (sockclient_pid > 0 )
		{
			int status;
            		wait(&status);
            		close(new_sockfd->iSocket);
			continue;
		}
		
		else if (sockclient_pid == 0 )
		{
			//do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__, "connected client [%s]....", inet_ntoa(g_stCli_addr.sin_addr));
			rot_close(sockfd);
			ret = process_command(new_sockfd);
			sleep(1);
			close (new_sockfd->iSocket);
			exit(0);
		}
		else
		{
			close (new_sockfd->iSocket);
			exit(0);
		}
		sleep(1);
	}

	return 0;
}
