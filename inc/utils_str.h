#ifndef _UTILS_STR_H__
#define _UTILS_STR_H__

#include <stdio.h>
#include <stdlib.h>

int rot_str_gettokslot(void);
void rot_str_returntokslot(int slot);
char *rot_str_xstrchr(char *string, int delimiter);
char *rot_str_xstrtok(char *string, int delimiter, int slot);
char *rot_str_xsplitat(char *string, int delimiter, int slot);
int rot_str_xparsestring(char *string, int delimiter, char **splitted_token, int ntoken);
int rot_str_isnum(char *arg);
int rot_str_isfilename(char *fn);
int rot_str_isusername(char *uname);
int rot_str_isgrpname(char *gname);
void rot_str_removetail_crlf(char *_sString);
void rot_str_trimLeftwhiteSpace(char *szSrc, char *szDest);
void rot_str_trimrightwhitespace(char *szSrc, char *szDest);
void rot_str_trimwhitespace(char *szSrc, char *szDest);
//char *xstrtok(char *string, int delimiter, int slot);
#endif //_UTILS_STR_H__
