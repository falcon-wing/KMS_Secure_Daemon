
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <ctype.h>

#include "monM_def.h"
#include "rot_pam_conf.h"
#include "libsrcUtils.h"
extern s_token *keyval;
extern char *g_strRot_D_RootPath;

char *tbuf;
int lines;

/// @brief
/// @param fp
/// @return
int pamconf_file_lines(FILE *fp)
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

/// @brief
/// @param buf
/// @return
char *pamconf_get_token(char *buf)
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

/// @brief
/// @param path
/// @return
int pamconf_read_conf(char *path)
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

    lines = pamconf_file_lines(fp);
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

        tok = pamconf_get_token(rbuf);
        if (tok != NULL)
        {
            strncpy(keyval[i].keywd, tok, L_KEYWD - 1);
            keyval[i].keywd[L_KEYWD - 1] = 0x00;
        }
        else
            continue;

        tok = pamconf_get_token(NULL);
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

    do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__,"test--004 pamconf_file_lines");
    lines = i;
    fclose(fp);
    return TRUE;
}

/// @brief
/// @param key
/// @param keybuf
/// @return
int pamconf_get_conf(const char *key, char *keybuf)
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

/// @brief
/// @param
/// @return
int pamconf_close_conf(void)
{
    if (keyval != NULL)
        free(keyval);
    keyval = NULL;

    return TRUE;
}

/// @brief
/// @return
int get_pam_mode()
{
    int ret = 0;

    return ret;
}

int get_rot_pam_op_mode(int *iMode)
{
    int ret = 0;
    char szOpMode[8] = {0};
    char szConfFilePath[MAX_FULLPATH_SIZE] = {0};
    *iMode = FALSE;
    do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__,"test--004(%s)",PAM_ACL_CONF);
    ret = pamconf_read_conf(PAM_ACL_CONF);
    if (ret == FALSE )
    {
        do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__,"test--005");
	return 0;
    }
/*
    if (g_strRot_D_RootPath == NULL)
    {
        do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, "[get_rot_pam_op_mode] root path is invalid...");
        // ERROR MSG
        return 0;
    }

    memset(szConfFilePath, 0x00, sizeof(szConfFilePath));
    snprintf(szConfFilePath, MAX_FULLPATH_SIZE, "%s/%s/%s", g_strRot_D_RootPath, ROT_CONF, ROT_PAMCONFILE);
    if (rot_file_isfile(szConfFilePath) == FALSE)
    {
        do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, "[get_rot_pam_op_mode] config file is not found...[%s]", szConfFilePath);
        // ERROR MSG
        return 0;
    }

    ret = pamconf_read_conf(szConfFilePath);
    if (ret == FALSE)
    {
        do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, "[get_rot_pam_op_mode] fail to read config .[%s]", szConfFilePath);
        return 0;
    }
*/
    do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__,"test-00600");
    //ret = pamconf_get_conf("ROT_PAM_OP_MODE", szOpMode);
    ret = true;
    sprintf (szOpMode, "ON");
    do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__,"test-006-1");
    if (ret == FALSE)
    {
        do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__,"test-006-2");
        //do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, "[get_rot_pam_op_mode] fail to work (pamconf_get_conf)");
        return 0;
    }

    if (szOpMode == NULL || strlen(szOpMode) <= 0)
    {
        do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__,"test-006-3");
        //do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, "[get_rot_pam_op_mode] szOpmode is invalid....");
        return 0;
    }
    else
    {

        do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__,"test-006-4");
        if (strcmp(szOpMode, "ON") == 0)
        {
            *iMode = TRUE;
        }
        else if (strcmp(szOpMode, "OFF") == 0)
        {
            *iMode = FALSE;
        }
        else
        {

            *iMode = FALSE;
        }
    }

    do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, __FILE__, __LINE__,"rwar 007");
    pamconf_close_conf();
    return TRUE;
}

int get_rot_pam_mfa_mode(int *iMode)
{
    int ret = 0;
    char szMfaOpMode[8] = {0};
    char szConfFilePath[MAX_FULLPATH_SIZE] = {0};
    *iMode = FALSE;

    ret = pamconf_read_conf(PAM_ACL_CONF);
    if (ret == FALSE )
    {
        return 0;
    }
    
    ret = pamconf_get_conf(ROT_PAM_MFA_MODE, szMfaOpMode);
    if (ret == FALSE)
    {
        do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, "[get_rot_pam_op_mode] fail to work (pamconf_get_conf)");
        return 0;
    }

    if (szMfaOpMode == NULL || strlen(szMfaOpMode) <= 0)
    {
        do_rotlog(ROTD_PRODUCT_NAME, 1, LV_INFO, "[get_rot_pam_op_mode] szOpmode is invalid....");
        return 0;
    }
    else
    {

        if (strcmp(szMfaOpMode, "ON") == 0)
        {
            *iMode = TRUE;
        }
        else if (strcmp(szMfaOpMode, "OFF") == 0)
        {
            *iMode = FALSE;
        }
        else
        {

            *iMode = FALSE;
        }
    }

    pamconf_close_conf();
    return TRUE;
}

#ifndef _TEST_WORK
int set_rot_pam_conf ( char * szErrMsg )
{
	int ret = 0;

	FILE * fp = NULL;
    	char szConfFilePath[MAX_FULLPATH_SIZE] = {0};
    	char szConfFileTmpPath[MAX_FULLPATH_SIZE] = {0};
    	char szConfFileOldPath[MAX_FULLPATH_SIZE] = {0};

    	char szLineBuf[1024] = {0};
    	snprintf(szConfFilePath, MAX_FULLPATH_SIZE, "%s",PAM_ACL_CONF);

	if (rot_file_isfile(szConfFilePath) == FALSE)
    	{
        	rot_file_createdir(szConfFilePath);
    	}

    	snprintf(szConfFileOldPath, MAX_FULLPATH_SIZE, "%s.old", szConfFilePath);
    	snprintf(szConfFileTmpPath, MAX_FULLPATH_SIZE, "%s.tmp", szConfFilePath);

	//
		//here code......
	//
	
	rename(szConfFilePath, szConfFileOldPath);
    	ret = rename(szConfFileTmpPath, szConfFilePath);
    	if( ret != 0)
    	{
        	//ERROR MESSAGE
        	return -1;
    	}
	return ret;
}

#endif

int set_rot_pam_op_mode(int iMode, char * szErrMsg )
{
    int ret = 0;
    FILE * fp = NULL;
    char szConfFilePath[MAX_FULLPATH_SIZE] = {0};
    char szConfFileTmpPath[MAX_FULLPATH_SIZE] = {0};
    char szConfFileOldPath[MAX_FULLPATH_SIZE] = {0};

    char szLineBuf[1024] = {0};

    //snprintf(szConfFilePath, MAX_FULLPATH_SIZE, "%s/%s/%s", g_strRot_D_RootPath, ROT_CONF, ROT_PAMCONFILE);
    snprintf(szConfFilePath, MAX_FULLPATH_SIZE, "%s",PAM_ACL_CONF);

    if (rot_file_isfile(szConfFilePath) == FALSE)
    {
        rot_file_createdir(szConfFilePath);
    }

    snprintf(szConfFileOldPath, MAX_FULLPATH_SIZE, "%s.old", szConfFilePath);
    snprintf(szConfFileTmpPath, MAX_FULLPATH_SIZE, "%s.tmp", szConfFilePath);

    //
    fp = fopen(szConfFileTmpPath, "w");
    if (fp == NULL)
    {
        /// ERROR MESSAGE
        return FALSE;
    }

    if (iMode == 1)
    {
        snprintf (szLineBuf, MAX_FULLPATH_SIZE, "%s = %s\n", ROT_PAM_OP_MODE, MODE_ON);
    }
    else
    {
        snprintf (szLineBuf, MAX_FULLPATH_SIZE, "%s = %s\n", ROT_PAM_OP_MODE, MODE_OFF);
    }

    
    fprintf (fp, "%s" , szLineBuf);

    // test
    memset (&szLineBuf, 0x00 , sizeof (szLineBuf ));
    snprintf (szLineBuf, MAX_FULLPATH_SIZE, "%s = %s\n", "ROT_PAM_DEFAULT_SERV_PORT", "4009");
    fprintf (fp, "%s",  szLineBuf);
    //

    rename(szConfFilePath, szConfFileOldPath);
    ret = rename(szConfFileTmpPath, szConfFilePath);
    if( ret != 0)
    {
        //ERROR MESSAGE
        return -1;
    }

    return TRUE;
}

//////
///
/*
<>
*/
int do_pamrule_get(int nRuleType)
{
    int ret = 0;
    FILE *pFileDesc = NULL;
    char szConfDir[MAX_FULLPATH_SIZE] = {0};
    char szRulePath[MAX_FULLPATH_SIZE] = {0};
    // g_strRot_D_RootPath

    snprintf(szConfDir, MAX_FULLPATH_SIZE, "%s",PAM_ACL_RULE_DIR);
    if (rot_file_isdir(szConfDir) != TRUE)
    {

        rot_file_createdir(szConfDir);
        return -1;
    }

    if (nRuleType == ROT_PAM_RULE_TYPE_USER)
    {
        snprintf(szRulePath, MAX_FULLPATH_SIZE, "%s%s", szConfDir, ROT_PAM_RULE_NAME_USER);
    }
    else if (nRuleType == ROT_PAM_RULE_TYPE_GROUP)
    {
        snprintf(szRulePath, MAX_FULLPATH_SIZE, "%s%s", szConfDir, ROT_PAM_RULE_NAME_GROUP);
    }
    else if (nRuleType == ROT_PAM_RULE_TYPE_DEFAULT)
    {
        snprintf(szRulePath, MAX_FULLPATH_SIZE, "%s%s", szConfDir, ROT_PAM_RULE_NAME_DEFAULT);
    }

    if (rot_file_isfile(szRulePath) == FALSE)
    {

        if (rot_file_create(szRulePath) == FALSE)
        {
            // ERROR MSG
        }

        return -1;
    }

    pFileDesc = rot_file_fopen(szRulePath, "r");
    if (pFileDesc == NULL)
    {

        // ERROR MSG

        return -1;
    }

    // rot_file_open_ex(szRulePath, "r");

    return ret;
}

