#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <ctype.h>
#include <stdbool.h>
#include "def.h"
//extern s_token *keyval;
s_token *keyval = NULL;
extern char g_szRootPath[MAX_FULLPATH_SIZE];
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

int get_monD_conf(monDLogconf_t * _Dconf, char * szErrMsg )
{
	int ret = 0;
	char szConfFilePath[MAX_FULLPATH_SIZE] = {0};
	char szLineBuf[1024] = {0};
	char *strCurrPath = NULL;
	//strCurrPath = rot_getcwd();
	//snprintf(szConfFilePath, MAX_FULLPATH_SIZE, "%s/%s/%s", strCurrPath, ROT_CONF, ROT_DCONFILE);

	memset (&szLineBuf, 0x00 , sizeof (szLineBuf));
	memset(&szConfFilePath, 0x00, sizeof(szConfFilePath));
	snprintf(szConfFilePath, MAX_FULLPATH_SIZE, "%s/%s/%s", g_szRootPath, ROT_CONF, ROT_DCONFILE);
	memset (_Dconf, 0x00 , sizeof ( monDLogconf_t));

	if (rot_file_isfile(szConfFilePath) == FALSE)
	{
		//do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO,__FILE__, __LINE__, "[get_rotD_conf] config file is not found...[%s]", szConfFilePath);
		// ERROR MSG
		return 0;
	}

	ret = rotdconf_read_conf( szConfFilePath);
	if (ret == FALSE)
	{
		//do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO,__FILE__, __LINE__, "[get_rotD_conf] fail to read config .[%s]", szConfFilePath);
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

    	rotdconf_close_conf();
    	return TRUE;
}
