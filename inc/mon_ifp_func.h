#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdbool.h>



bool chk_fw_org_rule (char * line, int* nOsIndex);
bool oper_fw_rule (int nOption, char * ruleline, char * szErrMsg);
