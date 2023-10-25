#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils_str.h"

///< PMA RULE>

char *rot_getrule_at_rulefile(char *_sString, int _nCnt, FILE *fp)
{
    while (fgets(_sString, _nCnt, fp))
    {
        rot_str_removetail_crlf(_sString);
        rot_str_trimwhitespace(_sString, _sString);

        if ( _sString[0] == '\0' || _sString[0] == '#')
        {
            continue;
        }

        return _sString;
    }
    return NULL;
}

char *rot_pam_getrule_at_rulefile(char *_sString, int _nCnt, FILE *fp)
{
    while (fgets(_sString, _nCnt, fp))
    {
        rot_str_removetail_crlf(_sString);
        rot_str_trimwhitespace(_sString, _sString);

        if ( _sString[0] == '\0' || _sString[0] == '#')
        {
            continue;
        }

        return _sString;
    }
    return NULL;
}

///< FW RULE>
char *rot_fw_getrrule_at_rulefile(char *_sString, int _nCnt, FILE *fp)
{
    return NULL;
}

//<SYSMON RULE>
char *rot_sysmon_getrrule_at_rulefile(char *_sString, int _nCnt, FILE *fp)
{
    return NULL;
}