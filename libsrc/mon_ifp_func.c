#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdbool.h>

#define MAX_BYDY_LEN 2048
#define MAX_TOKEN_SLOT 30
#define K_SEP_PACL_FIELD '|'
#define TRUE 1
#define FALSE 0
#define IDX_PAMRULE_MAX 7
#define E_RET -1
#define LINEBUF 1024

int nIPFtokslot[MAX_TOKEN_SLOT];
char *pIPFtokstr[MAX_TOKEN_SLOT];

#define FW_RULE_SEPARATOR " \t\n\r"
#define FW_RULE_SEPARATOR_PIPE "|"
#define FW_RULE_SEARCH_INPUTCHAIN_COUNT_STR "/sbin/iptables -L INPUT | /usr/bin/wc -l"
#define FW_RULE_SEARCH_OUTPUTCHAIN_COUNT_STR "/sbin/iptables -L OUTPUT | /usr/bin/wc -l"
#define FW_RULE_SEARCH_OUTPUTCHAIN_STR "/sbin/iptables -L OUTPUT -v -n --line-numbers"
#define FW_RULE_SEARCH_INPUTCHAIN_STR "/sbin/iptables -L INPUT -v -n --line-numbers"
#define FW_RULE_SEARCH_DOCKERUSERCHAIN_STR "/sbin/iptables -L DOCKER-USER -v -n --line-numbers"

enum fw_func
{
	FW_FUNC_ADD = 0,
	FW_FUNC_DEL,
	FW_FUNC_INS,
};

enum _FW_RULE_INDEX
{
	//	FW_RULE_INDEX_COMM 	= 0,
	FW_RULE_INDEX_CHAIN = 0,
	FW_RULE_INDEX_SOURCE,
	FW_RULE_INDEX_DESTINATION,
	FW_RULE_INDEX_PROTOCOL,
	FW_RULE_INDEX_SPORTS,
	FW_RULE_INDEX_DPORTS,
	FW_RULE_INDEX_TARGET,
	FW_RULE_INDEX_MAX
};

#define FW_RULE_COMM_ADD "-A"
#define FW_RULE_COMM_DEL "-D"
#define FW_RULE_COMM_INSERT "-I"

typedef struct _fw_comm_t
{
	char comm1[8];
	char comm2[8];
} _fw_comm;

_fw_comm fwcomm[3] = {
	{"A", "-A"},
	{"D", "-D"},
	{"I", "-I"}};

#define DEF_RULE_CNT 5

#define FW_RULE_DEF_ALLDENY "INPUT|*|*|tcp|-|*|DROP"

void init_IPFtokslot(void)
{
	int i;

	for (i = 0; i < MAX_TOKEN_SLOT; i++)
	{
		nIPFtokslot[i] = 0;
		pIPFtokstr[i] = (char *)0;
	}
}

int get_IPFtokslot(void)
{
	int i;

	for (i = 0; i < MAX_TOKEN_SLOT; i++)
	{
		if (nIPFtokslot[i] == 0)
		{
			nIPFtokslot[i] = 1;
			return i;
		}
	}

	return -1;
}

void return_IPFtokslot(int slot)
{
	nIPFtokslot[slot] = 0;
	pIPFtokstr[slot] = (char *)NULL;
}

char *xsplit_at_IPF(char *string, int delimiter, int slot)
{
	char *cp = (char *)NULL;
	char *ptstr = string;

	if (ptstr != (char *)NULL)
		pIPFtokstr[slot] = ptstr;

	if (pIPFtokstr[slot] == (char *)NULL)
		return (char *)NULL;

	if ((cp = strchr(pIPFtokstr[slot], delimiter)) != (char *)NULL)
	{
		*cp++ = 0x00;
		ptstr = cp;
		cp = pIPFtokstr[slot];
		pIPFtokstr[slot] = ptstr;
	}
	else /* End of Token */
	{
		cp = pIPFtokstr[slot];
		pIPFtokstr[slot] = (char *)NULL;
	}

	return (cp);
}

int IPF_xparse_string(char *string, int delimiter, char **splitted_token, int ntoken)
{
	int slot;
	int tcount = 0;
	char *tok = (char *)NULL;

	slot = get_IPFtokslot();
	if (slot == -1)
		return FALSE;

	for (tok = xsplit_at_IPF(string, delimiter, slot); tok != NULL; tok = xsplit_at_IPF((char *)NULL, delimiter, slot))
	{
		splitted_token[tcount] = tok;
		tcount++;
		if (tcount == ntoken) /* If token count is too larger than ntoken, just ignore the rest */
			break;
	}

	return_IPFtokslot(slot);

	if (tcount < ntoken)
		return E_RET;
	else
		return TRUE;
}

int fw_ruleitem_cnt(char *rule)
{
	int cnt = 0;

	char *token = strtok(rule, FW_RULE_SEPARATOR);
	if (token == NULL)
	{
		return 0;
	}

	cnt++;

	while (token != NULL)
	{

		token = strtok(NULL, FW_RULE_SEPARATOR);
		if (token != NULL)
			cnt++;
	}

	return cnt;
}

int fw_ruleitem_cnt_pipe(char *rule)
{
	int cnt = 0;

	char *token = strtok(rule, FW_RULE_SEPARATOR_PIPE);
	if (token == NULL)
	{
		return 0;
	}

	cnt++;

	while (token != NULL)
	{

		token = strtok(NULL, FW_RULE_SEPARATOR_PIPE);
		if (token != NULL)
			cnt++;
	}

	return cnt;
}

int pars_fw_rule(char *input, char ***parts)
{
	int count = 0, cnt = 0;
	char seps[5];
	char szTmp[LINEBUF];
	char **result;

	strcpy(seps, FW_RULE_SEPARATOR);
	sprintf(szTmp, "%s", input);

	cnt = fw_ruleitem_cnt(szTmp);
	result = (char **)malloc(cnt * sizeof(char *));

	char *token = strtok(input, seps);
	result[count] = token;
	while (token)
	{

		token = strtok(NULL, seps);
		if (token != NULL)
		{
			count++;
			result[count] = token;
		}
		else
			break;
	}

	*parts = result;

	return count;
}

int pars_fw_rule_type_pipe(char *input, char ***parts)
{
	int count = 0, cnt = 0;
	char seps[5];
	char szTmp[1024] = {0};
	char **result;
	char *token;

	strcpy(seps, FW_RULE_SEPARATOR_PIPE);
	sprintf(szTmp, "%s", input);
	cnt = fw_ruleitem_cnt_pipe(szTmp);

	token = strtok(input, seps);
	result = (char **)malloc(cnt * sizeof(char *));

	result[count] = token;
	while (token)
	{
		token = strtok(NULL, seps);
		if (token != NULL)
		{
			count++;
			result[count] = token;
		}
		else
			break;
	}

	*parts = result;

	return count;
}

bool oper_fw_rule(int nOption, char *ruleline, char *szErrMsg)
{

	int retval = 0;
	char command[1024] = {0};
	char *ptoken[FW_RULE_INDEX_MAX];
	memset(ptoken, 0x00, sizeof(ptoken));

	if (ruleline == NULL || strlen(ruleline) <= 0)
	{
		return false;
	}

	int ret = IPF_xparse_string(ruleline, K_SEP_PACL_FIELD, ptoken, IDX_PAMRULE_MAX);
	if (ptoken == NULL)
	{
		return false;
	}

	else
	{
		strcat(command, "sudo /sbin/iptables ");

		if (nOption == (int)FW_FUNC_ADD)
		{
			strcat(command, fwcomm[FW_FUNC_ADD].comm2);
		}
		else if (nOption == (int)FW_FUNC_DEL)
		{
			strcat(command, fwcomm[FW_FUNC_DEL].comm2);
		}

		else if (nOption == (int)FW_FUNC_INS)
		{
			strcat(command, fwcomm[FW_FUNC_INS].comm2);
		}
		else
		{
			return false;
		}

		////
		if (strcmp(ptoken[FW_RULE_INDEX_CHAIN], "INPUT") == 0)
		{
			strcat(command, " ");
			strcat(command, "INPUT");
		}
		else if (strcmp(ptoken[FW_RULE_INDEX_CHAIN], "OUTPUT") == 0)
		{
			strcat(command, " ");
			strcat(command, "OUTPUT");
		}
		else
		{
			return false;
		}

		////
		if (strlen(ptoken[FW_RULE_INDEX_SOURCE]) > 0)
		{
			if (strcmp(ptoken[FW_RULE_INDEX_SOURCE], "*") == 0)
			{
			}

			else
			{
				strcat(command, " ");
				strcat(command, "-s");
				strcat(command, " ");

				strcat(command, ptoken[FW_RULE_INDEX_SOURCE]);
			}
		}
		else
		{
		}

		//
		if (strlen(ptoken[FW_RULE_INDEX_DESTINATION]) > 0)
		{
			if (strcmp(ptoken[FW_RULE_INDEX_DESTINATION], "*") == 0)
			{
			}

			else
			{

				strcat(command, " ");
				strcat(command, "-d");
				strcat(command, " ");

				strcat(command, ptoken[FW_RULE_INDEX_DESTINATION]);
			}
		}
		else
		{
		}

		//
		if (strlen(ptoken[FW_RULE_INDEX_PROTOCOL]) > 0)
		{
			if (strcmp(ptoken[FW_RULE_INDEX_PROTOCOL], "*") == 0)
			{
				strcat(command, " -p ");
				strcat(command, "all");
			}

			else
			{

				strcat(command, " -p ");
				strcat(command, ptoken[FW_RULE_INDEX_PROTOCOL]);
			}
		}
		else
		{
		}

		//
		if (strlen(ptoken[FW_RULE_INDEX_DPORTS]) > 0 && strcmp(ptoken[FW_RULE_INDEX_DPORTS], "-") != 0)
		{
			strcat(command, " --dport ");
			if (strcmp(ptoken[FW_RULE_INDEX_DPORTS], "*") == 0)
			{
				strcat(command, "0:65535");
			}
			else
			{
				strcat(command, ptoken[FW_RULE_INDEX_DPORTS]);
			}
		}
		else
		{
		}

		if (strlen(ptoken[FW_RULE_INDEX_SPORTS]) > 0 && strcmp(ptoken[FW_RULE_INDEX_SPORTS], "-") != 0)
		{
			strcat(command, " --sport ");
			strcat(command, ptoken[FW_RULE_INDEX_SPORTS]);
		}
		else
		{
		}

		////

		if (strlen(ptoken[FW_RULE_INDEX_TARGET]) > 0)
		{
			if (strcmp(ptoken[FW_RULE_INDEX_TARGET], "ACCEPT") == 0)
			{
				strcat(command, " -j ");
				strcat(command, "ACCEPT");
			}
			else if (strcmp(ptoken[FW_RULE_INDEX_TARGET], "DROP") == 0)
			{
				strcat(command, " -j ");
				strcat(command, "DROP");
			}
			else if (strcmp(ptoken[FW_RULE_INDEX_TARGET], "REJECT") == 0)
			{
				strcat(command, " -j ");
				strcat(command, "REJECT");
			}

			else
			{
				return false;
			}
		}
		else
		{
		}
		//strcat (command, " LO");

		retval = system(command);
		//	printf ("system command = [%s]\n\n", command);
		sprintf(szErrMsg, "result code [%d]", retval);
	}
	return true;
}

bool chk_fw_org_rule(char *line, int *nOsIndex)
{
	int i = 0, j = 0, nRuleCnt = 0, cnt = 0;
	FILE *pfd = NULL;
	char szIptablePath_cnt[1024] = {0};
	char szIptablePath[1024] = {0};
	char **parts;
	char **partsChkTarget;
	char linebuf[LINEBUF];
	char *ptoken[IDX_PAMRULE_MAX];
	memset(ptoken, 0x00, sizeof(ptoken) );

	sprintf(szIptablePath_cnt, "%s", FW_RULE_SEARCH_INPUTCHAIN_COUNT_STR);
	char szLineBak[LINEBUF] = {0};
	char szTemps[1024] = {0};
	sprintf(szTemps, "%s", line);

	int ret = pars_fw_rule_type_pipe(szTemps, &partsChkTarget);
	int x = 0;
	bool result = false;

	pfd = (FILE *)popen(szIptablePath_cnt, "r");
	fgets(linebuf, LINEBUF, pfd);
	pclose(pfd);

	nRuleCnt = atoi(linebuf);

	int nFlage = 0;
	memset(linebuf, 0x00, sizeof(linebuf));

	sprintf(szIptablePath, "%s", FW_RULE_SEARCH_INPUTCHAIN_STR);
	pfd = (FILE *)popen(szIptablePath, "r");

	bool bchkTarget = false, bchkProtocol = false, bchkSourceIp = false, bchkDesstinationIp = false, bchkSPort = false, bchkDPort = false;
	bool bchkExistSport = false, bchkExistDport = false;
	int nFindIndex = -1;

	for (i = 0; i < nRuleCnt; i++)
	{
		memset(szLineBak, 0x00, sizeof(char) * LINEBUF);
		fgets(linebuf, LINEBUF, pfd);

		sprintf(szLineBak, "%s", linebuf);
		szLineBak[strlen(szLineBak) - 1] = '\n';
		cnt = pars_fw_rule(linebuf, &parts);
		if (atoi(parts[0]) <= 0)
		{
			continue;
		}

		bchkTarget = false, bchkProtocol = false, bchkSourceIp = false, bchkDesstinationIp = false, bchkSPort = false, bchkDPort = false;
		bchkExistSport = false, bchkExistDport = false;
		nFindIndex = 0;

		char *pTmp;
		for (j = 0; j <= cnt; j++)
		{
			if (j == 0)
			{
				if (atoi(parts[0]) <= 0)
				{
					break;
				}
				nFindIndex = atoi(parts[0]);
			}
			else if (j == 3) // ACCEPT/REJECT....
			{
				if (strcmp(parts[j], partsChkTarget[FW_RULE_INDEX_TARGET]) == 0)
				{
					bchkTarget = true;
				}
			}

			else if (j == 4) // PROTOCOL
			{
				if ((strcmp(parts[j], "all") == 0) || (strcmp(parts[j], partsChkTarget[FW_RULE_INDEX_PROTOCOL]) == 0))
				{
					bchkProtocol = true;
				}
			}

			else if (j == 8) // SOURCE IP
			{
				if (((strcmp(parts[j], "0.0.0.0/0") == 0) && (strcmp(partsChkTarget[FW_RULE_INDEX_SOURCE], "*") == 0)) || (strcmp(parts[j], partsChkTarget[FW_RULE_INDEX_SOURCE]) == 0))
				{
					bchkSourceIp = true;
				}
			}

			else if (j == 9) // DESTINATION IP
			{
				if (((strcmp(parts[j], "0.0.0.0/0") == 0) && (strcmp(partsChkTarget[FW_RULE_INDEX_DESTINATION], "*") == 0)) || (strcmp(parts[j], partsChkTarget[FW_RULE_INDEX_DESTINATION]) == 0))
				{
					bchkDesstinationIp = true;
				}
			}

			else
			{
				char *pTmp1, *pTmp2;
				char *pTmp = strstr(parts[j], "dpts");
				if (pTmp)
				{
					bchkExistDport = true;
					if (strcmp(partsChkTarget[FW_RULE_INDEX_DPORTS], "-") == 0)
					{
						bchkDPort = false;
					}
					else
					{
						pTmp1 = strchr(pTmp, 58);
						if (pTmp1 && (pTmp1 + 1))
						{
							char *pItem = strstr((pTmp1 + 1), partsChkTarget[FW_RULE_INDEX_DPORTS]);
							if (pItem)
							{
								bchkDPort = true;
							}
						}
					}
				}
				else
				{
					pTmp = strstr(parts[j], "dpt");
					if (pTmp)
					{
						bchkExistDport = true;

						if (strcmp(partsChkTarget[FW_RULE_INDEX_DPORTS], "-") == 0)
						{
							bchkDPort = false;
						}
						else
						{
							pTmp1 = strchr(pTmp, 58);
							if (pTmp1 && (pTmp1 + 1))
							{
								char *pItem = strstr((pTmp1 + 1), partsChkTarget[FW_RULE_INDEX_DPORTS]);
								if (pItem)
								{
									char *pPortData = (pTmp1 + 1);
									pTmp2 = strchr(pPortData, 58);
									if (pTmp2)
									{

										char *pPortPars = strtok(pPortData, ":");
										if (pPortPars)
										{
											pPortPars = strtok(NULL, ":");
											if (strcmp(pPortPars, partsChkTarget[FW_RULE_INDEX_DPORTS]) == 0)
											{
												bchkDPort = true;
											}
										}
										else
										{
											if (strcmp((pTmp1 + 1), partsChkTarget[FW_RULE_INDEX_DPORTS]) == 0)
											{
												bchkDPort = true;
											}
										}
									}
									else
									{
										if (strcmp((pTmp1 + 1), partsChkTarget[FW_RULE_INDEX_DPORTS]) == 0)
										{
											bchkDPort = true;
										}
									}
								}
							}
							else
							{
								if (strcmp(partsChkTarget[FW_RULE_INDEX_DPORTS], "*") == 0)
								{
									bchkDPort = true;
								}
							}
						}
					}
					else
					{
						if ((strcmp(partsChkTarget[FW_RULE_INDEX_DPORTS], "-") == 0) /* || (strcmp (partsChkTarget[FW_RULE_INDEX_DPORTS], "*") == 0)*/)
						{
							bchkDPort = true;
						}
					}
				}

				pTmp = strstr(parts[j], "spts");
				if (pTmp)
				{
					bchkExistSport = true;
					if (strcmp(partsChkTarget[FW_RULE_INDEX_SPORTS], "-") == 0)
					{
						bchkSPort = false;
					}
					else
					{
						pTmp1 = strchr(pTmp, 58);
						if (pTmp1 && (pTmp1 + 1))
						{
							char *pItem = strstr((pTmp1 + 1), partsChkTarget[FW_RULE_INDEX_SPORTS]);
							if (pItem)
							{
								bchkSPort = true;
							}
						}
					}
				}
				else
				{
					pTmp = strstr(parts[j], "spt");
					if (pTmp)
					{
						if (strcmp(partsChkTarget[FW_RULE_INDEX_SPORTS], "-") == 0)
						{
							bchkSPort = false;
						}
						else
						{
							bchkExistSport = true;
							pTmp1 = strchr(pTmp, 58);
							if (pTmp1 && (pTmp1 + 1))
							{
								char *pItem = strstr((pTmp1 + 1), partsChkTarget[FW_RULE_INDEX_SPORTS]);
								if (pItem)
								{
									bchkSPort = true;
								}
							}
						}
					}
					else
					{
						if (strcmp(partsChkTarget[FW_RULE_INDEX_SPORTS], "-") == 0)
						{
							bchkSPort = true;
						}
					}
				}
			}
		}

		if (bchkExistDport == false && bchkDPort == false)
		{
			if (partsChkTarget[FW_RULE_INDEX_DPORTS] == NULL || strlen(partsChkTarget[FW_RULE_INDEX_DPORTS]) <= 0)
			{
				bchkDPort = true;
			}
			else
			{
				if (strcmp(partsChkTarget[FW_RULE_INDEX_DPORTS], "*") == 0)
				{
					bchkDPort = TRUE;
				}
			}
		}

		if (bchkExistSport == false && bchkSPort == false)
		{
			if (partsChkTarget[FW_RULE_INDEX_SPORTS] == NULL || strlen(partsChkTarget[FW_RULE_INDEX_SPORTS]) <= 0)
			{
				bchkSPort = true;
			}
		}

		if (bchkTarget == true && bchkProtocol == true && bchkSourceIp == true && bchkDesstinationIp == true && bchkSPort == true && bchkDPort == true)
		{
			result = true;
			*nOsIndex = nFindIndex;
		}
		else
		{
			//printf ("NOT MATCH RULE......[%s]>>>[%s]\n\n>>[%d%d%d%d%d%d]\n\n",line, szLineBak,bchkTarget , bchkProtocol , bchkSourceIp , bchkDesstinationIp , bchkSPort, bchkDPort );
		}
	}

	return result;
}
