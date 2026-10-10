#include <linux/fs.h>
#include <linux/file.h>
#include <linux/version.h>
#include <linux/ctype.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include "mstring.h"
//#include "debug.h"
//#include "plugbase.h" /* needed for fasthex() */



/****************************************************************
 *
 *  Function: mSplit()
 *
 *  Purpose: Splits a string into tokens non-destructively.
 *
 *  Parameters:
 *      char *str => the string to be split
 *      char *sep => a string of token seperaters
 *      int max_strs => how many tokens should be returned
 *      int *toks => place to store the number of tokens found in str
 *      char meta => the "escape metacharacter", treat the character
 *                   after this character as a literal and "escape" a
 *                   seperator
 *
 *  Returns:
 *      2D char array with one token per "row" of the returned
 *      array.
 *
 ****************************************************************/
char **mSplit(char *str, const char *sep, int max_strs, int *toks, char meta)
{
    char **retstr;      /* 2D array which is returned to caller */
    const char *idx;          /* index pointer into str */
    char *end;          /* ptr to end of str */
    const char *sep_end;      /* ptr to end of seperator string */
    const char *sep_idx;      /* index ptr into seperator string */
    int len = 0;        /* length of current token string */
    int curr_str = 0;       /* current index into the 2D return array */
    char last_char = (char) 0xFF;

    if(!toks) return NULL;

    *toks = 0;

    if (!str) return NULL;
    /*
     * find the ends of the respective passed strings so our while() loops
     * know where to stop
     */
    sep_end = sep + strlen(sep);
    end = (char *)(str + strlen(str));

    /* remove trailing whitespace */
    while(isspace((int) *(end - 1)) && ((end - 1) >= str))
        *(--end) = '\0';    /* -1 because of NULL */

    /* set our indexing pointers */
    sep_idx = sep;
    idx = str;

    /*
     * alloc space for the return string, this is where the pointers to the
     * tokens will be stored
     */

    if((retstr = (char **) kmalloc((sizeof(char **) * max_strs), GFP_KERNEL)) == NULL) {
        //D("malloc");
        //FatalPrintError("malloc");
        return NULL;
    }

    max_strs--;
    /* loop thru each letter in the string being tokenized */
    while(idx < end)
    {
        /* loop thru each seperator string char */
        while(sep_idx < sep_end)
        {
            /*
             * if the current string-indexed char matches the current
             * seperator char...
             */
            if((*idx == *sep_idx) && (last_char != meta))
            {
                /* if there's something to store... */
                if(len > 0)
                {
                    if(curr_str <= max_strs)
                    {
                        /* allocate space for the new token */
                        if((retstr[curr_str] = (char *)
                                    kmalloc((sizeof(char) * len) + 1, GFP_KERNEL)) == NULL)
                        {
                            //E("malloc");
                            //FatalPrintError("malloc");
                            return NULL;
                        }

                        /* copy the token into the return string array */
                        memcpy(retstr[curr_str], (idx - len), len);
                        retstr[curr_str][len] = 0;
                        /* twiddle the necessary pointers and vars */
                        len = 0;
                        curr_str++;
                        last_char = *idx;
                        idx++;
                    }
                   /*
                     * if we've gotten all the tokens requested, return the
                     * list
                     */
                    if(curr_str >= max_strs)
                    {
                        while(isspace((int) *idx))
                            idx++;

                        len = end - idx;
                        //fflush(stdout);

                        if((retstr[curr_str] = (char *)
                                    kmalloc((sizeof(char) * len) + 1, GFP_KERNEL)) == NULL) {
                            //E("malloc");
                            //FatalPrintError("malloc");
                            return NULL;
                        }
                        memcpy(retstr[curr_str], idx, len);
                        retstr[curr_str][len] = 0;

                        *toks = curr_str + 1;
                        return retstr;
                    }
                }
                else
                    /*
                     * otherwise, the previous char was a seperator as well,
                     * and we should just continue
                     */
                {
                    last_char = *idx;
                    idx++;
                    /* make sure to reset this so we test all the sep. chars */
                    sep_idx = sep;
                    len = 0;
                }
            }
            else
            {
                /* go to the next seperator */
                sep_idx++;
            }
        }

        sep_idx = sep;
        len++;
        last_char = *idx;
        idx++;
    }

    /* put the last string into the list */

    if(len > 0)
    {
        if((retstr[curr_str] = (char *)
                    kmalloc((sizeof(char) * len) + 1, GFP_KERNEL)) == NULL) {
            //E("malloc");
            //FatalPrintError("malloc");
            return NULL;
        }
        memcpy(retstr[curr_str], (idx - len), len);
        retstr[curr_str][len] = 0;

        *toks = curr_str + 1;
    }

    /* return the token list */
    return retstr;
}




/****************************************************************
 *
 * Free the buffer allocated by mSplit().
 *
 * char** toks = NULL;
 * int num_toks = 0;
 * toks = (str, " ", 2, &num_toks, 0);
 * mSplitFree(&toks, num_toks);
 *
 * At this point, toks is again NULL.
 *
 ****************************************************************/
void mSplitFree(char ***pbuf, int num_toks)
{
    int i;
    char** buf;  /* array of string pointers */

    if( pbuf==NULL || *pbuf==NULL )
    {
        return;
    }

    buf = *pbuf;

    for( i=0; i<num_toks; i++ )
    {
        if( buf[i] != NULL )
        {
            kfree( buf[i] );
            buf[i] = NULL;
        }
    }

    kfree(buf);
    *pbuf = NULL;
}




