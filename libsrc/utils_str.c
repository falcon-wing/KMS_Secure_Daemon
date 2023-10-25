#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <ctype.h>
#include "utils_str.h"
#include "monM_def.h"

int ntokslot[MAX_TOKEN_SLOT] = {
    0,
};
char *ptokstr[MAX_TOKEN_SLOT] = {
    (char *)NULL,
};

int rot_str_gettokslot(void)
{
    int i;

    for (i = 0; i < MAX_TOKEN_SLOT; i++)
    {
        if (ntokslot[i] == 0)
        {
            ntokslot[i] = 1;
            return i;
        }
    }

    return -1;
}

void rot_str_returntokslot(int slot)
{
    ntokslot[slot] = 0;
    ptokstr[slot] = (char *)NULL;
}

char *rot_str_xstrchr(char *string, int delimiter)
{
    char *tp = (char *)NULL;
    int qm_detected = FALSE; /* Quotation Mark is found */

    if (string == (char *)NULL)
        return (char *)NULL;

    tp = string;
    while (*tp != 0x00)
    {
        if ((*tp == '\"') || (*tp == '\''))
        {
            if (qm_detected == FALSE)
                qm_detected = TRUE;
            else
                qm_detected = FALSE;
        }
        else
        {
            if ((*tp == delimiter) && (qm_detected == FALSE))
                return tp;
        }

        *tp++;
    }

    return (char *)NULL;
}

char *rot_str_xstrtok(char *string, int delimiter, int slot)
{
    char *cp = (char *)NULL;
    char *ptstr = string;

    if (ptstr != (char *)NULL)
        ptokstr[slot] = ptstr;

    if (ptokstr[slot] == (char *)NULL)
        return (char *)NULL;

    if ((cp = rot_str_xstrchr(ptokstr[slot], delimiter)) != (char *)NULL)
    {
        *cp++ = 0x00;
        ptstr = cp;
        cp = ptokstr[slot];
        ptokstr[slot] = ptstr;
    }
    else /* End of Token */
    {
        cp = ptokstr[slot];
        ptokstr[slot] = (char *)NULL;
    }

    return (cp);
}

char *rot_str_xsplitat(char *string, int delimiter, int slot)
{
    char *cp = (char *)NULL;
    char *ptstr = string;

    if (ptstr != (char *)NULL)
        ptokstr[slot] = ptstr;

    if (ptokstr[slot] == (char *)NULL) // || ptokstr[slot][0] == 0x00)
        return (char *)NULL;

    if ((cp = strchr(ptokstr[slot], delimiter)) != (char *)NULL)
    {
        *cp++ = 0x00;
        ptstr = cp;
        cp = ptokstr[slot];
        ptokstr[slot] = ptstr;
    }
    else /* End of Token */
    {
        cp = ptokstr[slot];
        ptokstr[slot] = (char *)NULL;
    }

    return (cp);
}

/*
char *xstrtok(char *string, int delimiter, int slot)
{
        char *cp = (char *)NULL;
        char *ptstr = string;

        if (ptstr != (char *)NULL)
                ptokstr[slot] = ptstr;

        if (ptokstr[slot] == (char *)NULL)              // || ptokstr[slot][0] == 0x00)
                return (char *)NULL;

        if ((cp = xstrchr(ptokstr[slot], delimiter)) != (char *)NULL)
        {
                *cp++ = 0x00;
                ptstr = cp;
                cp = ptokstr[slot];
                ptokstr[slot] = ptstr;
        }
        else            // End of Token 
        {
                cp = ptokstr[slot];
                ptokstr[slot] = (char *)NULL;
        }

        return (cp);
}

*/

int rot_str_xparsestring(char *string, int delimiter, char **splitted_token, int ntoken)
{
    int slot;
    int tcount = 0;
    char *tok = (char *)NULL;

    slot = rot_str_gettokslot();
    if (slot == -1)
        return FALSE;

    for (tok = rot_str_xsplitat(string, delimiter, slot); tok != NULL; tok = rot_str_xsplitat((char *)NULL, delimiter, slot))
    {
        if (tok == NULL)
            break;

        splitted_token[tcount] = tok;
        tcount++;
        if (tcount == ntoken) /* If token count is too larger than ntoken, just ignore the rest */
            break;
    }

    rot_str_returntokslot(slot);

    if (tcount < ntoken)
        return E_RET;
    else
        return TRUE;
}

int rot_str_isnum(char *arg)
{
    int i;

    if (*arg == 0x00)
        return FALSE;

    for (i = 0; *(arg + i) != NULLC; i++)
    {
        if (i == 0)
        {
            if (!isdigit((int)*arg) && (*arg != '-'))
                return FALSE;
        }
        else
        {
            if (!isdigit((int)*(arg + i)))
                return FALSE;
        }
    }

    return TRUE;
}

int rot_str_isfilename(char *fn)
{
    int i;

    for (i = 0; *(fn + i) != NULLC; i++)
        if (!isalnum((int)*(fn + i)) && (*(fn + i) != '_') && (*(fn + i) != '-') && (*(fn + i) != '.'))
            return FALSE;

    return TRUE;
}

int rot_str_isusername(char *uname)
{
    int i;

    for (i = 0; *(uname + i) != NULLC; i++)
        if (!isalnum((int)*(uname + i)) && (*(uname + i) != '_') && (*(uname + i) != '-') && (*(uname + i) != '.')
#ifdef WIN32
            && (*(uname + i) != ' ')
#endif /* WIN32 */
        )
            return FALSE;

    return TRUE;
}

int rot_str_isgrpname(char *gname)
{
    int i;

    for (i = 0; *(gname + i) != NULLC; i++)
        if (!isalnum((int)*(gname + i)) && (*(gname + i) != '_') && (*(gname + i) != '-') && (*(gname + i) != '.'))
            return FALSE;

    return TRUE;
}

void rot_str_removetail_crlf(char *_sString)
{
    int i;

    i = strlen(_sString);

    while (i > 0)
    {
        if ((_sString[i - 1] == 0x0D) || (_sString[i - 1] == 0x0A))
            _sString[i - 1] = '\0';
        else
            break;
        i--;
    }
}

void rot_str_trimLeftwhitespace(char *szSrc, char *szDest)
{
    char *ptr;

    if ((szSrc == NULL) || (szDest == NULL))
        return;

    ptr = szSrc;
    while (*ptr != '\0')
    {
        if (isspace((int)*ptr))
            ptr++;
        else
            break;
    }

    strcpy(szDest, ptr);
}

void rot_str_trimrightwhitespace(char *szSrc, char *szDest)
{
    char *ptr;

    ptr = szSrc + strlen(szSrc) - 1;
    while (ptr >= szSrc)
    {
        if (isspace((int)*ptr))
            ptr--;
        else
            break;
    }

    if (ptr >= szSrc)
    {
        strncpy(szDest, szSrc, ptr - szSrc + 1);
        szDest[ptr - szSrc + 1] = '\0';
    }
    else
        szDest[0] = '\0';
}

void rot_str_trimwhitespace(char *szSrc, char *szDest)
{
    rot_str_trimLeftwhitespace(szSrc, szDest);
    rot_str_trimrightwhitespace(szDest, szDest);
}









