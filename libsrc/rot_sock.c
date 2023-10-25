#include "rot_sock.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "monM_def.h"

struct sockaddr_in g_stServ_addr, g_stCli_addr;

/*
 *
*/
void init_socket(LPSOCKETINFO _pSock, char _cTMode)
{
    if (_pSock == NULL)
        return;
    memset(_pSock, 0x00, sizeof(struct SOCKET_INFO));
    _pSock->iSocket = INVALID_SOCKET;
    _pSock->cTMode = SOCK_TEXT_MODE;
}

/*
 *
*/
int isConnected(LPSOCKETINFO _pSock)
{
    if (_pSock == NULL)
        return FALSE;

    if (_pSock->iSocket == INVALID_SOCKET)
        return FALSE;

    return TRUE;
}

char * get_ipadddr_for_socket(SOCKET sockfd)
{
        char * ipaddr;
        int size;
	char  myIP [ 16 ];
        struct sockaddr_in sockAddr;
	socklen_t  len =  sizeof ( sockAddr );
	
	getsockname ( sockfd , ( struct  sockaddr  * ) & sockAddr , & len );
	inet_ntop ( AF_INET , & sockAddr.sin_addr , myIP , sizeof ( myIP ));
        ipaddr = (char*) malloc (16);
        strcpy (ipaddr, myIP);

        return ipaddr;
}

/*
 *
*/
int rot_socket(LPSOCKETINFO _pSock, int _af, int _type, int _protocol)
{
    if (_pSock == NULL)
        return FALSE;

    _pSock->iSocket = socket(_af, _type, _protocol);
    if (_pSock->iSocket == INVALID_SOCKET)
        return E_RET;

    return TRUE;
}

/*
 *
*/
int rot_setsockopt(LPSOCKETINFO _pSock, int _level, int _optname, const char *_optval, int _option)
{
    if (_pSock == NULL)
        return FALSE;

    return setsockopt(_pSock->iSocket, _level, _optname, _optval, _option);
}

/*
 *
*/
int rot_select(LPSOCKETINFO _pSock, fd_set *_pRead, fd_set *_pWrite, fd_set *_pExcept, struct timeval *_pTime)
{
    if (_pSock == NULL)
        return FALSE;

    if (_pSock->iSocket == INVALID_SOCKET)
        return FALSE;

    return select(_pSock->iSocket, _pRead, _pWrite, _pExcept, _pTime);
}

/*
 *
*/
int rot_bind(LPSOCKETINFO _pSock, const struct sockaddr *_pAddr, int _nLen)
{
    if (_pSock == NULL)
        return FALSE;

    return bind(_pSock->iSocket, _pAddr, _nLen);
}

/*
 *
*/
int rot_listen(LPSOCKETINFO _pSock, int _nBacklog)
{
    if (_pSock == NULL)
        return FALSE;

    return listen(_pSock->iSocket, _nBacklog);
}

/*
 *
*/
int rot_connect(LPSOCKETINFO _pSock, const struct sockaddr *_pAddr, int _nLen)
{
    if (_pSock == NULL)
        return E_RET;

    return connect(_pSock->iSocket, _pAddr, _nLen);
}

/*
 *
*/
int rot_close(LPSOCKETINFO _pSock)
{
    if (_pSock == NULL)
        return FALSE;

    sleep(1);

    return closesocket(_pSock->iSocket);
}

/*
 *
*/
int rot_recv(LPSOCKETINFO _pSock, char *_pcBuf, int _nLen, int _nFlags)
{
    int iLen = 0, iRecv = 0;

    if (_pSock == NULL)
        return FALSE;

    while (1)
    {
        iRecv = recv(_pSock->iSocket, &_pcBuf[iLen], _nLen - iLen, _nFlags);
        if (iRecv <= 0)
            return iRecv;
        iLen = iLen + iRecv;
        if (iLen == _nLen)
            break;
    }

    return iLen;
}

/*
 *
*/
int rot_send(LPSOCKETINFO _pSock, const char *_pcBuf, int _nLen, int _nFlags)
{
    if (_pSock == NULL)
        return FALSE;

    return send(_pSock->iSocket, _pcBuf, _nLen, _nFlags);
}

/*
 *
*/
int rot_read(LPSOCKETINFO _pSock, char *_pcBuf, int _nLen, int _nTimeoutCheck)
{
    int iLen = 0, iRecv = 0, nRet;

    fd_set read_fds;
    struct timeval stTimeVal;

    if (_nTimeoutCheck == USE_TIMEOUT_CHECK)
    {
        stTimeVal.tv_sec = TIMEOUT_CHECK_SEC;
        stTimeVal.tv_usec = 0;

        FD_ZERO(&read_fds);
        FD_SET(_pSock->iSocket, &read_fds);

        nRet = select(_pSock->iSocket + 1, &read_fds, NULL, NULL, &stTimeVal);
        if (nRet <= 0)
        {
            // do_log("LM_READ", LV_ERR, "Fail to receive Socket Check data. - Socket Timeout occured.");
            return E_RET;
        }
    }

    if (_pSock == NULL)
        return FALSE;

    while (1)
    {
        iRecv = read(_pSock->iSocket, &_pcBuf[iLen], _nLen - iLen);
        if (iRecv <= 0)
            return iRecv;
        iLen = iLen + iRecv;
        if (iLen == _nLen)
            break;
    }

    return iLen;
}

/*
 *
*/
int rot_write(LPSOCKETINFO _pSock, const char *_pcBuf, int _nLen)
{
#define Send write

    if (_pSock == NULL)
        return FALSE;

    return Send(_pSock->iSocket, _pcBuf, _nLen);
}

