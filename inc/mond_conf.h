#ifndef _MOND_CONF_H__
#define _MOND_CONF_H__

#include <stdio.h>
#include <stdlib.h>
#include "monM_def.h"

int rotdconf_file_lines(FILE *fp);
char *rotdconf_token(char *buf);
int rotdconf_read_conf(char *path);
int rotdconf_get_conf(const char *key, char *keybuf);
int rotdconf_close_conf(void);
int get_monD_conf(monDLogconf_t * _Dconf, char * szErrMsg );
int set_monD_conf(monDLogconf_t * _Dconf, char * szErrMsg );
int rotdconf_get_confV2(const char *path, const char *key, char *keybuf);
int set_conf_type_of_string(int _KeyIndex, char * _data, char * szErrMsg);
char * get_conf_type_of_string(int _KeyIndex, char * szErrMsg);
int rotdconf_get_conf(const char *key, char *keybuf);

int get_rot_pam_op_mode_v2();
#endif
