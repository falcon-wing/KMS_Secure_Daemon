#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <json-c/json.h>

#define PORTNUM 5001

#define CMD_PAM_BASE_V2 500100
//#define CMD_PAM_BASE 500100
#define CMD_PAM_GET_OP_MODE             CMD_PAM_BASE_V2 + 1        //500101
#define CMD_PAM_SET_OP_MODE             CMD_PAM_BASE_V2 + 2        //500102
#define CMD_PAM_GET_RULE                CMD_PAM_BASE_V2 + 3        //500103
#define CMD_PAM_SET_RULE                CMD_PAM_BASE_V2 + 4        //500104
//#define CMD_PAM_GET_LOGS              CMD_PAM_BASE_V2 + 5

#define CMD_PAM_GET_MFA_ACT             CMD_PAM_BASE_V2 + 5        //500105
#define CMD_PAM_SET_MFA_ACT             CMD_PAM_BASE_V2 + 6        //500106

#define CMD_FW_BASE 500200
#define CMD_FW_ADD_RULE                 CMD_FW_BASE     + 1  
#define CMD_FW_DEL_RULE                 CMD_FW_BASE     + 2
#define CMD_FW_SET_RULE                 CMD_FW_BASE     + 3


#define CMD_PAM_BASE 500300
#ifndef CMD_MOND_GET_MODDE
#define CMD_MOND_GET_MODDE      CMD_PAM_BASE + 1   //500301
#endif

#ifndef CMD_MOND_SET_MODDE
#define CMD_MOND_SET_MODDE      CMD_PAM_BASE + 2        //500302
#endif

#ifndef CMD_MOND_GET_TARCONTAINERLIST
#define CMD_MOND_GET_TARCONTAINERLIST   CMD_PAM_BASE + 3        //500303
#endif

#ifndef CMD_MOND_SET_TARCONTAINERLIST
#define CMD_MOND_SET_TARCONTAINERLIST   CMD_PAM_BASE + 4        //500304
#endif

#ifndef CMD_MOND_GET_TARDAEMONLIST
#define CMD_MOND_GET_TARDAEMONLIST      CMD_PAM_BASE + 5        //500305
#endif

#ifndef CMD_MOND_SET_TARDAEMONLIST
#define CMD_MOND_SET_TARDAEMONLIST      CMD_PAM_BASE + 6        //500306
#endif

#ifndef CMD_MOND_GET_CPUINFO
#define CMD_MOND_GET_CPUINFO            CMD_PAM_BASE + 7        //500307
#endif

#ifndef CMD_MOND_GET_MEMINFO
#define CMD_MOND_GET_MEMINFO            CMD_PAM_BASE + 8        //500308
#endif

#ifndef CMD_MOND_GET_DISKIOINFO
#define CMD_MOND_GET_DISKIOINFO         CMD_PAM_BASE + 9        //500309
#endif

#define MAX_BYDY_LEN 4096
#define MAX_HADERDATA_SIZE 1192

int main(int argc, char ** argv)
{
	int sd, len, i;
	struct sockaddr_in sin;
	char buf[MAX_HADERDATA_SIZE + MAX_BYDY_LEN];
	int trid = 0;
	if (argc < 2)
	{
		printf (" pls insert parameter...\n");
		return 0;

	}

	trid = atoi(argv[1]);
	if ((trid > CMD_MOND_GET_DISKIOINFO) || (trid < CMD_PAM_BASE_V2 ))
	{
	//	printf (" invalied param...\n");
	//	return 0;
	}

	json_object *jsMainObj  = json_object_new_object();
    	//json_object_object_add(jsMainObj,"cmd",json_object_new_string("run"));
    	//json_object *jsReqObj = json_object_new_object();
    //	json_object *jstargetObj = json_object_new_object();
    	json_object *jsheaderObj = json_object_new_object();
    	json_object *jsbodyObj = json_object_new_object();

//"INPUT|*|*|tcp|-|22|ACCEPT"
//	json_object_object_add(jstargetObj,"url",json_object_new_string("/kms/get-monitoring-information"));

	json_object_object_add(jsheaderObj,"trid",json_object_new_string(argv[1]));
    //	json_object_object_add(jsheaderObj,"function",json_object_new_string("get-information"));

	json_object_object_add(jsbodyObj,"pam_rule_type", json_object_new_string("USER"));
	/*
	json_object_object_add(jsbodyObj,"ipf_tar_rule", json_object_new_string(argv[2]));
	json_object_object_add(jsbodyObj,"pam_op_mode", json_object_new_string(argv[3]));
	*/
	json_object_object_add(jsbodyObj,"pam_rule_data", json_object_new_string(argv[2]));

//	json_object_object_add(jsReqObj,"target", jstargetObj);
    	json_object_object_add(jsMainObj,"header", jsheaderObj);
    	json_object_object_add(jsMainObj,"body", jsbodyObj);

	//json_object_object_add(jsMainObj,"request", jsReqObj);
	sprintf (buf, "%s", json_object_get_string(jsMainObj));

	memset((char *)&sin, '\0', sizeof(sin));
	char recvbuf[MAX_HADERDATA_SIZE + MAX_BYDY_LEN];
    	sin.sin_family = AF_INET;
    	sin.sin_port = htons(PORTNUM);
    	sin.sin_addr.s_addr = inet_addr("127.0.0.1");

	printf ("create socket...(%d)\n",PORTNUM);

	if((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        	perror("socket");
        	exit(1);
    	}

	printf ("connect...5555555555555\n");
	if(connect(sd, (struct sockaddr *)&sin, sizeof(sin))) {
        	perror("connect");
        	exit(1);
    	}

	printf ("send data : %s\n", buf);

	if (send(sd, buf, strlen(buf) + 1, 0 ) == -1)
	{
		perror("send");
		exit(0);
	}

	printf ("recv ...\n");

	len = recv(sd, recvbuf, sizeof(recvbuf), 0);
	if (len < 0 )
	{
		for (i = 0 ; i < 3 ; i ++)
		{
		    sleep(1);
		    len = recv(sd, recvbuf, len, 0);
		    if (len > 0)
			break;
		}

		if (len < 0)
		    printf ("(E) recv() error[%d]!!!\n", len);


	}

	printf("==> From Server : (%d)|%s|\n", len,recvbuf);
	close(sd);
	return 0;
}

