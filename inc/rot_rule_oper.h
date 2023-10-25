
#ifndef _ROT_RULE_OPER_H_
#define _ROT_RULE_OPER_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


char *rot_getrule_at_rulefile(char *_sString, int _nCnt, FILE *fp);
char *rot_pam_getrule_at_rulefile(char *_sString, int _nCnt, FILE *fp);
char *rot_fw_getrrule_at_rulefile(char *_sString, int _nCnt, FILE *fp);
char *rot_sysmon_getrrule_at_rulefile(char *_sString, int _nCnt, FILE *fp);

#endif