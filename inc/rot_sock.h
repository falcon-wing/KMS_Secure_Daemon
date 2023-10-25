#ifndef _ROT_SOCK_H__
#define _ROT_SOCK_H__

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define INVALID_SOCKET 0xFFFFFFFF /* -1 int */
#define closesocket close

#ifndef _TYPE_SOCKET
#define _TYPE_SOCKET
typedef unsigned int SOCKET;
#endif /* _TYPE_SOCKET */

#ifndef SOCK_TEXT_MODE
#define SOCK_TEXT_MODE 0
#endif

struct SOCKET_INFO
{
    char cTMode;
    SOCKET iSocket; // 0 : not connect
};
typedef struct SOCKET_INFO *LPSOCKETINFO;

char * get_ipadddr_for_socket(SOCKET sockfd);


#endif
