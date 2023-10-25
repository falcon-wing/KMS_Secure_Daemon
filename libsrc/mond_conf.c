#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <ctype.h>
#include <stdbool.h>
#include "monM_def.h"
#include "mond_conf.h"
#include <errno.h>
//#include <error.h>i
/*
#include "rot_conf.h"
#include "rot_def.h"
*/
#include "rot_utils.h"

extern char *g_strRot_D_RootPath;
extern char g_szRootPath[MAX_FULLPATH_SIZE + 1];

extern s_token *keyval;
char *tbuf;
int lines;

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

int get_rot_pam_op_mode_v2()
{
    int ret = 0, nResult = 0;
    char szOpMode[8] = {0};
    char szConfFilePath[MAX_FULLPATH_SIZE] = {0};
    //*iMode = 0;
    ret = rotdconf_read_conf(PAM_ACL_CONF);
    if (ret == FALSE )
    {
	return 0;
    }

    ret = rotdconf_get_conf("ROT_PAM_OP_MODE", szOpMode);
    //ret = true;
    //sprintf (szOpMode, "ON");
    do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__,"test-006-1..(%s)",szOpMode);
    if (ret == FALSE)
    {
        return 0;
    }

    if (szOpMode == NULL || strlen(szOpMode) <= 0)
    {
        return 0;
    }
    else
    {

        if (strcmp(szOpMode, "ON") == 0)
        {
            nResult = 1;      
        }
        else if (strcmp(szOpMode, "OFF") == 0)
        {
            nResult = 0;
        }
        else
        {

            nResult = 1;
        }
    }

    rotdconf_close_conf();
    do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__,"test-006-3..(%d)",nResult);
    return nResult;
}

int get_monD_conf(monDLogconf_t * _Dconf, char * szErrMsg )
{
    int ret = 0;
    char szConfFilePath[MAX_FULLPATH_SIZE] = {0};
    char szLineBuf[1024] = {0};
    char *strCurrPath = NULL;
    strCurrPath = rot_getcwd();
    //snprintf(szConfFilePath, MAX_FULLPATH_SIZE, "%s/%s/%s", strCurrPath, ROT_CONF, ROT_DCONFILE);

    memset (&szLineBuf, 0x00 , sizeof (szLineBuf));
    memset(&szConfFilePath, 0x00, sizeof(szConfFilePath));
/*    if (g_strRot_D_RootPath == NULL)
    {
        do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, "[get_rotD_conf] fail to load config file...(%d)", errno);
        return 0;
    }
*/
    //snprintf(szConfFilePath, MAX_FULLPATH_SIZE, "%s/%s/%s", g_strRot_D_RootPath, ROT_CONF, ROT_DCONFILE);
    snprintf(szConfFilePath, MAX_FULLPATH_SIZE, "%s/%s/%s", g_szRootPath, ROT_CONF, ROT_DCONFILE);
    memset (_Dconf, 0x00 , sizeof ( monDLogconf_t));

    if (rot_file_isfile(szConfFilePath) == FALSE)
    {
        do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO,__FILE__, __LINE__, "[get_rotD_conf] config file is not found...[%s]", szConfFilePath);
        // ERROR MSG
        return 0;
    }

    ret = rotdconf_read_conf( szConfFilePath);
    if (ret == FALSE)
    {
        do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO,__FILE__, __LINE__, "[get_rotD_conf] fail to read config .[%s]", szConfFilePath);
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

    ret = rotdconf_get_conf(MOND_DOCKER_URL, szLineBuf );
    if (ret == TRUE )
    {
	sprintf (_Dconf->szDockerUrl, "%s" , szLineBuf );
    }
    else
    {
	sprintf (_Dconf->szDockerUrl, "");
    }
    // MOND_LOG_LASTDATE

    ret = rotdconf_get_conf(MOND_LOG_LASTDATE, szLineBuf );
    if (ret == TRUE )
    {
	sprintf (_Dconf->szLogLastDate, "%s", szLineBuf);
    }
    else
    {
	//sprintf (_Dconf->szLogLastDate, "%lu",(unsigned long)time(NULL));
	sprintf (_Dconf->szLogLastDate, "");
    }
	
    rotdconf_close_conf();		
    return TRUE;
}


int set_monD_conf(monDLogconf_t * _Dconf, char * szErrMsg )
{
    int ret = 0;
    FILE * fp = NULL;
    char szConfFilePath[MAX_FULLPATH_SIZE] = {0};
    char szConfFileTmpPath[MAX_FULLPATH_SIZE] = {0};
    char szConfFileOldPath[MAX_FULLPATH_SIZE] = {0};

    char szLineBuf[1024] = {0};
/*
    if (g_strRot_D_RootPath == NULL || strlen (g_strRot_D_RootPath) <= 0)
    {
	sprintf (g_strRot_D_RootPath, "%s", ROOT_PATH);
    }
  */  
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
        //ERROR MESSAGE
        return -1;
    }

    fclose(fp);
    return TRUE;
}

int set_conf_type_of_int(char * _KeyName, int _data, char * szErrMsg)
{
	int ret = 0;
	BOOL bRet = FALSE;
	monDLogconf_t conf;
	memset (&conf, 0x00 , sizeof (conf ));

	bRet = get_monD_conf(&conf, szErrMsg );
	if (bRet == TRUE )
	{
		//if (
	}
	return ret;
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
	//return 1;
	if (bRet == TRUE)
	{
		bRet = 1;
	}

	return ret;
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
			sprintf (szRetData, "%s", szData);
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












	


