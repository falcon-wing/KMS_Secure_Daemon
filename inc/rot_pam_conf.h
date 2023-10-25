#ifndef ROT_PAM_CONF_H_
#define ROT_PAM_CONF_H_
#include <stdio.h>
#include <stdlib.h>

//
#ifndef ROT_PAM_RULE_TYPE_USER
#define ROT_PAM_RULE_TYPE_USER 1
#endif

#ifndef ROT_PAM_RULE_TYPE_GROUP
#define ROT_PAM_RULE_TYPE_GROUP 2
#endif 

#ifndef ROT_PAM_RULE_TYPE_DEFAULT
#define ROT_PAM_RULE_TYPE_DEFAULT 3
#endif

#ifndef ROT_PAM_RULE_NAME_USER
#define ROT_PAM_RULE_NAME_USER "rot_pam_user.rule"
#endif 

#ifndef ROT_PAM_RULE_NAME_GROUP
#define ROT_PAM_RULE_NAME_GROUP "rot_pam_group.rule"
#endif

#ifndef ROT_PAM_RULE_NAME_DEFAULT
#define ROT_PAM_RULE_NAME_DEFAULT "rot_pam_default.rule"
#endif

#ifndef ROT_PAM_CONF_DIR_PATH
#define ROT_PAM_CONF_DIR_PATH "/etc/security"
#endif

#ifndef ROT_PAM_CONF_FILE
#define ROT_PAM_CONF_FILE "rotPam.conf"
#endif



//

int file_lines(FILE *fp);
// char *get_token(char *buf);
int read_conf(char *path);
int get_conf(const char *key, char *keybuf);
int close_conf(void);

int get_rot_pam_op_mode(int *iMode);
int set_rot_pam_op_mode(int iMode, char * szErrMsg );

#endif
