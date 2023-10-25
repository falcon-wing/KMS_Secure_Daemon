#ifndef _UTILS_H__
#define _UTILS_H__

int already_running(char *szPidFile);
void daemonization();
void SetSignal();
char *rot_getcwd();
//size_t cb(void *data, size_t size, size_t nmemb, void *clientp);
size_t read_callback(char *dest, size_t size, size_t nmemb, void *userp);
bool NeedUpdateDate();
char * get_conf_type_of_string(int _KeyIndex, char * szErrMsg);
int set_conf_type_of_string(int _KeyIndex, char * _data, char * szErrMsg);

char *make_response_json(char *_sCmd, char *retCode, char *_sTrid, char *_retMessage, char * _skeyName, char *_sData, int _nType);



#endif
