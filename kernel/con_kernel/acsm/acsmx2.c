/*
**   acsmx2.c
**
**   Multi-Pattern Search Engine
**
**   Aho-Corasick State Machine - version 2.0
**
**   Supports both Non-Deterministic and Deterministic Finite Automata
**
**
**   Reference - Efficient String matching: An Aid to Bibliographic Search
**               Alfred V Aho and Margaret J Corasick
**               Bell Labratories
**               Copyright(C) 1975 Association for Computing Machinery,Inc
**
**   +++
**   +++ Version 1.0 notes - Marc Norton:
**   +++
**
**   Original implementation based on the 4 algorithms in the paper by Aho & Corasick,
**   some implementation ideas from 'Practical Algorithms in C', and some
**   of my own.
**
**   1) Finds all occurrences of all patterns within a text.
**
**   +++
**   +++ Version 2.0 Notes - Marc Norton/Dan Roelker:
**   +++
**
**   New implementation modifies the state table storage and access model to use
**   compacted sparse vector storage. Dan Roelker and I hammered this strategy out
**   amongst many others in order to reduce memory usage and improve caching performance.
**   The memory usage is greatly reduced, we only use 1/4 of what we use to. The caching
**   performance is better in pure benchmarking tests, but does not show overall improvement
**   in Snort.  Unfortunately, once a pattern match test has been performed Snort moves on to doing
**   many other things before we get back to a patteren match test, so the cache is voided.
**
**   This versions has better caching performance characteristics, reduced memory,
**   more state table storage options, and requires no a priori case conversions.
**   It does maintain the same public interface.(Snort only used banded storage).
**
**     1) Supports NFA and DFA state machines, and basic keyword state machines
**     2) Initial transition table uses Linked Lists
**     3) Improved state table memory options. NFA and DFA state
**        transition tables are converted to one of 4 formats during compilation.
**        a) Full matrix
**        b) Sparse matrix
**        c) Banded matrix(Default-this is the only one used in snort)
**        d) Sparse-Banded matrix
**     4) Added support for acstate_t in .h file so we can compile states as
**        16, or 32 bit state values for another reduction in memory consumption,
**        smaller states allows more of the state table to be cached, and improves
**        performance on x86-P4.  Your mileage may vary, especially on risc systems.
**     5) Added a bool to each state transition list to indicate if there is a matching
**        pattern in the state. This prevents us from accessing another data array
**        and can improve caching/performance.
**     6) The search functions are very sensitive, don't change them without extensive testing,
**        or you'll just spoil the caching and prefetching opportunities.
**
**   Extras for fellow pattern matchers:
**    The table below explains the storage format used at each step.
**    You can use an NFA or DFA to match with, the NFA is slower but tiny - set the structure directly.
**    You can use any of the 4 storage modes above -full,sparse,banded,sparse-bands, set the structure directly.
**    For applications where you have lots of data and a pattern set to search, this version was up to 3x faster
**    than the previous verion, due to caching performance. This cannot be fully realized in Snort yet,
**    but other applications may have better caching opportunities.
**    Snort only needs to use the banded or full storage.
**
**  Transition table format at each processing stage.
**  -------------------------------------------------
**  Patterns -> Keyword State Table(List)
**  Keyword State Table -> NFA(List)
**  NFA -> DFA(List)
**  DFA(List)-> Sparse Rows  O(m-avg # transitions per state)
**        -> Banded Rows  O(1)
**            -> Sparse-Banded Rows O(nb-# bands)
**        -> Full Matrix  O(1)
**
*
* Notes:
*
* 8/28/06
* man - Sparse and SparseBands - fixed off by one in calculating matching index
*       SparseBands changed ps increment to 2+n to increment between bands.
*/

#include <linux/kernel.h> //kcalloc-GFP_ATOMIC
#include <linux/ctype.h> //toupper,isprint
#include <linux/slab.h>  //kmalloc,kfree
#include <linux/string.h> //memcpy
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/mm.h>
#include <linux/seq_file.h>
#include <linux/errno.h>
#include <linux/limits.h>
#include "acsmx2.h"
#include "gnHead.h"
#include "utils/utils.h"
#include "defense/defense_inner.h"

#if 0
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,19,0)
#define GET_ACSM_RULES_DATA(inode) pde_data(inode)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
#define GET_ACSM_RULES_DATA(inode) PDE_DATA(inode)
#else
#define GET_ACSM_RULES_DATA(inode) PDE(inode)->data
#endif
#endif

#define ACSMMATCHLIST_LOCK    

/*
* Used to statistics malloc's(and free's) times 
* max_memory used to statistics malloc's memory size 
*/
size_t max_memory = 0;


/*
* Open acsm info print
*/
int s_verbose = 0;

/*
*
*/
typedef struct acsm_summary_s
{
    unsigned    num_states;
    unsigned    num_transitions;
    ACSM_STRUCT2 acsm;
} acsm_summary_t;

/*
*
*/
static acsm_summary_t summary= {0,0};

/*
** Case Translation Table 字符大小写转换表
*/
static unsigned char xlatcase[256];
/*
* 
*/
static void init_xlatcase(void)
{
    int i;
    for(i = 0; i < 256; i++)
    {
        xlatcase[i] = toupper(i); //全部存为大写
    }
}
/*
*    Case Conversion
*    d即dest，s即src，m为长度
*/
static inline void ConvertCaseEx(unsigned char *d, unsigned char *s, int m)
{
    int i;
#ifdef XXXX //很遗憾不知道为什么没有开启，估计是移植的时候没读懂下面的代码
    int n;
    n   = m & 3; //3是mask 为了获取右移2位以后被覆盖的值
    m >>= 2;     //右移2位，这么做是因为想让for每次循环能处理4个字符加快速度。

    for(i = 0; i < m; i++)
    {
        d[0] = xlatcase[ s[0] ];
        d[2] = xlatcase[ s[2] ];
        d[1] = xlatcase[ s[1] ];
        d[3] = xlatcase[ s[3] ];
        d+=4;
        s+=4;
    }
    //因为m>>2，其实就是m/4，那么n应该=m%4才对，而m&3的结果就是取余的结果，这都归功于左移，见笔记 
    for(i=0; i < n; i++)
    {
        d[i] = xlatcase[ s[i] ];
    }
#else
    for(i=0; i < m; i++)
    {
        d[i] = xlatcase[ s[i] ];
    }

#endif
}

/*
*
*/
void acsmSetVerbose2(int n)
{
    s_verbose = 1;
}

/*
*
*/
void * AC_MALLOC(size_t n)
{
    void *p;

    //p = __kmalloc(n, GFP_ATOMIC | __GFP_ZERO);
    p = kzalloc(n, GFP_ATOMIC);
    if(p)
    {
        //ALERT("AC_MALLOC p: %p, size: %d\n", p, n);
        max_memory += n;
    }
	else
	{
        printk("%s(%d),AC_MALLOC fail,[%ld]\n",__FUNCTION__,__LINE__,n);
	}
    return p;
}


/*
*
*/
void AC_FREE(void *p)
{
    if(p)
    {
        //ALERT("AC_FREE p: %p\n", p);
		kfree(p);
    }
}


/*
*    Simple QUEUE NODE
*/
typedef struct _qnode
{
    int state;
    struct _qnode *next;
}QNODE;

/*
*    Simple QUEUE Structure
*/
typedef struct _queue
{
    QNODE * head, *tail;
    int count;
}QUEUE;

/*
*   Initialize the queue
*/
static void queue_init(QUEUE * s)
{
    s->head = s->tail = 0;
    s->count= 0;
}

/*
*  Find a State in the queue
*/
static int queue_find(QUEUE * s, int state)
{
    QNODE * q;
    q = s->head;
    while(q)
    {
        if(q->state == state) return 1;
        q = q->next;
    }
    return 0;
}

/*
*  Add Tail Item to queue(FiFo/LiLo)
*/
static void queue_add(QUEUE * s, int state)
{
    QNODE * q;

    if(queue_find(s, state)) return;

    if(!s->head)
    {
        q = s->tail = s->head =(QNODE *)AC_MALLOC(sizeof(QNODE));
        if(!q)
        {
            MEMASSERT("ACSM-No Memory: %s!\n",__func__);
            return;
        }
        q->state = state;
        q->next = 0;
    }
    else
    {
        q =(QNODE *)AC_MALLOC(sizeof(QNODE));
        if(!q)
        {
            MEMASSERT("ACSM-No Memory: %s!\n",__func__);
            return;
        }
        q->state = state;
        q->next = 0;
        s->tail->next = q;
        s->tail = q;
    }
    s->count++;
}


/*
*  Remove Head Item from queue
*/
static int queue_remove(QUEUE * s)
{
    int state = 0;
    QNODE * q;
    if(s->head)
    {
        q       = s->head;
        state   = q->state;
        s->head = s->head->next;
        s->count--;

        if(!s->head)
        {
            s->tail = 0;
            s->count = 0;
        }
        AC_FREE(q);
    }
    return state;
}


/*
*   Return items in the queue
*/
static int queue_count(QUEUE * s)
{
    return s->count;
}


/*
*  Free the queue
*/
static void queue_free(QUEUE * s)
{
    while(queue_count(s))
    {
        queue_remove(s);
    }
}

/*
*  Get Next State-NFA
*  state初始是0，则匹配起来是从开始状态去查的，然后记录每次查之后的状态
*  input是一个字符即对应一个状态，state是当前状态
*  返回值是下一个状态
*/
static int List_GetNextState(ACSM_STRUCT2 * acsm, int state, int input)
{
    trans_node_t * t = acsm->acsmTransTable[state];

    while (t)
    {
        if (t->key == input)
        {
            return t->next_state;
        }
        t=t->next;
    }

    if (state == 0)
    {
        return 0; // 如果找到最后也没有在状态0找到该字符就返回0
    }
    
    /* Fail state 如果当前状态不是0那么说明还匹配了几个字符，应该在当前状态下插入新的状态 */
    return ACSM_FAIL_STATE2; 
}

/*
*  Get Next State-DFA
*  通过输入的字符input和当前状态state获取下一个状态，δ：Q×Σ→Q
*/
static int List_GetNextState2(ACSM_STRUCT2 * acsm, int state, int input)
{
    trans_node_t * t = acsm->acsmTransTable[state];

    while (t)
    {
        if (t->key == input)
        {
            return t->next_state;
        }
        t = t->next;
    }

    return 0; /* default state */
}
/*
*  Put Next State - Head insertion, and transition updates
*  添加一个新的状态，即从当前状态输入input后跳转到的状态。
*/
static int List_PutNextState(ACSM_STRUCT2 * acsm, int state, unsigned int input, int next_state)
{
    trans_node_t * p;
    trans_node_t * tnew;

// printf("List_PutNextState: state=%d, input='%c', next_state=%d\n",state,input,next_state);


    /* Check if the transition already exists, if so just update the next_state
     * 该函数如果是在初始化时调用的话该while语句是不会走的因为next_state的实参是acsm->acsmNumStates */
    p = acsm->acsmTransTable[state];
    while (p)
    {
        if (p->key == (acstate_t)input)  /* transition already exists - reset the next state */
        {
            p->next_state = (acstate_t)next_state;
            return 0;
        }
        p = p->next;
    }

    /* Definitely not an existing transition - add it */
    tnew = (trans_node_t*)AC_MALLOC(sizeof(trans_node_t));
    if (!tnew)
    {
        return -1;
    }

    tnew->key        = (acstate_t)input;
    tnew->next_state = (acstate_t)next_state;
    
    /* 将当前状态节点插入到当前状态表内，state之前。第一次tnew->next是NULL */
    //tnew->next       = 0;
    tnew->next = acsm->acsmTransTable[state];
    acsm->acsmTransTable[state] = tnew;

    acsm->acsmNumTrans++;

    return 0;
}
/*
*   Free the entire transition table
*/
static int List_FreeTransTable(ACSM_STRUCT2 * acsm)
{
    int i;
    trans_node_t * t, *p;

    if(!acsm->acsmTransTable) return 0;

    for(i=0; i< acsm->acsmMaxStates; i++)
    {
        t = acsm->acsmTransTable[i];

        while(t)
        {
            p = t->next;
            AC_FREE(t);
            t = p;
            max_memory -= sizeof(trans_node_t);
        }
    }

    AC_FREE(acsm->acsmTransTable);

    max_memory -= sizeof(void*) * acsm->acsmMaxStates;

    acsm->acsmTransTable = 0;

    return 0;
}

/*
*
*/
/*
static
int List_FreeList(trans_node_t * t)
{
  int tcnt=0;

  trans_node_t *p;

  while(t)
  {
       p = t->next;
       free(t);
       t = p;
       max_memory -= sizeof(trans_node_t);
       tcnt++;
   }

   return tcnt;
}
*/

/*
*    Print the trans table to stdout
*/
static int List_PrintTransTable(ACSM_STRUCT2 * acsm)
{
    int i;
    trans_node_t * t;
    ACSM_PATTERN2 * patrn;

    if(!acsm->acsmTransTable) return 0;

    ALERT("Print Transition Table- %d active states\n", acsm->acsmNumStates);

    for(i=0; i< acsm->acsmNumStates; i++)
    {
        t = acsm->acsmTransTable[i];

        ALERT("state %3d: ",i);

        while(t)
        {
            if(isprint(t->key))
            {
                ALERT("%3c->%-5d\t",t->key,t->next_state);
            }
            else
            {
                ALERT("%3d->%-5d\t",t->key,t->next_state);
            }
            t = t->next;
        }

        patrn =acsm->acsmMatchList[i];

        while(patrn)
        {
            ALERT("%.*s ",patrn->n,patrn->patrn);

            patrn = patrn->next;
        }

        ALERT("\n");
    }
    return 0;
}


/*
*   Converts row of states from list to a full vector format
*/
static int List_ConvToFull(ACSM_STRUCT2 * acsm, acstate_t state, acstate_t * full)
{
    int tcnt = 0;
    trans_node_t * t = acsm->acsmTransTable[ state ];

    memset(full,0,sizeof(acstate_t)*acsm->acsmAlphabetSize);

    if(!t) return 0;

    while(t)
    {
        full[ t->key ] = t->next_state;
        tcnt++;
        t = t->next;
    }
    return tcnt;
}

/*
*   Copy a Match List Entry - don't dup the pattern data
*/
static ACSM_PATTERN2 * CopyMatchListEntry(ACSM_PATTERN2 * px)
{
    ACSM_PATTERN2 * p;

    p =(ACSM_PATTERN2 *)AC_MALLOC(sizeof(ACSM_PATTERN2));

    if(!p)
    {
        ALERT("ACSM-No Memory: CopyMatchListEntry!\n");
        return NULL;

    }

    memcpy(p, px, sizeof(ACSM_PATTERN2));

    p->next = 0;

    return p;
}

/*
*  Check if a pattern is in the list already,
*  validate it using the 'id' field. This must be unique
*  for every pattern.
*/
/*
static
int FindMatchListEntry(ACSM_STRUCT2 * acsm, int state, ACSM_PATTERN2 * px)
{
  ACSM_PATTERN2 * p;

  p = acsm->acsmMatchList[state];
  while(p)
  {
    if(p->id == px->id) return 1;
    p = p->next;
  }

  return 0;
}
*/


/*
*  Add a pattern to the list of patterns terminated at this state
*  Insert at front of list
*  该函数将当前的模式添加到匹配成功链表中.也就是说当state状态时表明该模式匹配到了
*/
static void AddMatchListEntry(ACSM_STRUCT2 * acsm, int state, ACSM_PATTERN2 * px)
{
    ACSM_PATTERN2 * p;

    p =(ACSM_PATTERN2 *)AC_MALLOC(sizeof(ACSM_PATTERN2));

    MEMASSERT(p, "AddMatchListEntry");

    memcpy(p, px, sizeof(ACSM_PATTERN2));

    p->next = acsm->acsmMatchList[state];

    acsm->acsmMatchList[state] = p;
}

/* 
   状态机内的关键字进行状态转换的编译
   Add each Pattern to the State Table - This forms a keywords state table */
static void AddPatternStates(ACSM_STRUCT2 * acsm, ACSM_PATTERN2 * p)
{
    int             state, next, n;
    unsigned char * pattern;
    unsigned int    tpattern; //没什么用

    n       = p->n;
    pattern = p->patrn;
    state   = 0;  // 初始是0，则匹配起来是从开始状态去查的，然后记录每次查之后的状态

    if(s_verbose)
    {
        ALERT(" Begin AddPatternStates: acsmNumStates=%d\n",acsm->acsmNumStates);
    }
    if(s_verbose)
    {
        ALERT("    adding '%.*s', nocase=%d\n", n,p->patrn, p->nocase);
    }

    /*
    *  Match up pattern with existing states
    *  按现有的状态表对当前要安装的字符串进行查找，看看有没有现成的状态能匹配到
    *  该模式，或者最大能匹配到哪个模式，然后将这个状态返回。
    *  如果有的话n==0了state也记录了这个状态，然后退出交由下面的过程进行操作。
    *  如果没有就分匹配到一部分还是一直都是0状态。break后交由后面过程进行操作。
    *  第一个pattern这个for就直接过（break）了
    */
    for(; n > 0; pattern++, n--)
    {
        if(s_verbose)
        {
            ALERT(" find char='%c'\n", *pattern);
        }
        tpattern =(unsigned int)(*pattern);
        /* state初始是0，则匹配是从开始状态去查的，然后记录每次查之后的状态 */
        next = List_GetNextState(acsm, state, *pattern);
        if(next == ACSM_FAIL_STATE2 || next == 0)
        {
            break;
        }
        state = next;
    }

    /*
    *   Add new states for the rest of the pattern bytes, 1 state per byte
    *   添加一个新的状态节点到当前状态表。
    *   n是上面for循环经过查找之后剩余的n。pattern也是。都是剩余的。
    */
    for (; n > 0; pattern++, n--)
    {
        if (s_verbose)
        {
            ALERT(" add char='%c' state=%d NumStates=%d\n", *pattern, state, acsm->acsmNumStates);
        }

        acsm->acsmNumStates++;
        tpattern =(unsigned int)(*pattern);
        /* 将一个字符添加到当前状态表，acsm->acsmNumStates是当前状态表的最大状态数，也就是空闲条目的第一条。 */
        List_PutNextState(acsm, state, *pattern, acsm->acsmNumStates);
        state = acsm->acsmNumStates; // 添加以后当前的状态就转换到了添加字符以后的状态
    }

    /* 当将当前模式添加进状态表后，那么当前的状态是state，也是整个串匹配成功的状态，所以将该模式添加进匹配成功表 */
    AddMatchListEntry(acsm, state, p);

    if (s_verbose)
    {
        ALERT(" End AddPatternStates: acsmNumStates=%d\n",acsm->acsmNumStates);
    }
}

/*
*   Build A Non-Deterministic Finite Automata 不确定有限自动机
*   The keyword state table must already be built, via AddPatternStates().
*/
static void Build_NFA(ACSM_STRUCT2 * acsm)
{
    int r, s, i;
    QUEUE q, *queue = &q;
    acstate_t     * FailState = acsm->acsmFailState;
    ACSM_PATTERN2 ** MatchList = acsm->acsmMatchList;
    ACSM_PATTERN2  * mlist,* px;

    /* Init a Queue */
    queue_init(queue);


    /* Add the state 0 transitions 1st, the states at depth 1, fail to state 0 */
    for (i = 0; i < acsm->acsmAlphabetSize; i++)
    {
        s = List_GetNextState2(acsm, 0, i);
        if (s)
        {
            queue_add(queue, s);
            FailState[s] = 0;
        }
    }

    /* Build the fail state successive layer of transitions */
    while(queue_count(queue) > 0)
    {
        r = queue_remove(queue);

        /* Find Final States for any Failure */
        for(i = 0; i < acsm->acsmAlphabetSize; i++)
        {
            int fs, next;

            s = List_GetNextState(acsm,r,i);

            if(s != ACSM_FAIL_STATE2)
            {
                queue_add(queue, s);

                fs = FailState[r];

                /*
                 *  Locate the next valid state for 'i' starting at fs
                 */
                while((next=List_GetNextState(acsm,fs,i)) == ACSM_FAIL_STATE2)
                {
                    fs = FailState[fs];
                }

                /*
                 *  Update 's' state failure state to point to the next valid state
                 */
                FailState[s] = next;

                /*
                 *  Copy 'next'states MatchList to 's' states MatchList,
                 *  we copy them so each list can be AC_FREE'd later,
                 *  else we could just manipulate pointers to fake the copy.
                 */
                for(mlist = MatchList[next];
                        mlist;
                        mlist = mlist->next)
                {
                    px = CopyMatchListEntry(mlist);

                    /* Insert at front of MatchList */
                    px->next = MatchList[s];
                    MatchList[s] = px;
                }
            }
        }
    }

    /* Clean up the queue */
    queue_free(queue);

    if(s_verbose)
    {
        ALERT("End Build_NFA: NumStates=%d\n",acsm->acsmNumStates);
    }
}

/*
*   Build Deterministic Finite Automata from the NFA
*/
static void Convert_NFA_To_DFA(ACSM_STRUCT2 * acsm)
{
    int i, r, s, cFailState;
    QUEUE  q, *queue = &q;
    acstate_t * FailState = acsm->acsmFailState;

    /* Init a Queue */
    queue_init(queue);

    /* Add the state 0 transitions 1st */
    for(i=0; i<acsm->acsmAlphabetSize; i++)
    {
        s = List_GetNextState(acsm,0,i);
        if(s != 0)
        {
            queue_add(queue, s);
        }
    }

    /* Start building the next layer of transitions */
    while(queue_count(queue) > 0)
    {
        r = queue_remove(queue);

        /* Process this states layer */
        for(i = 0; i < acsm->acsmAlphabetSize; i++)
        {
            s = List_GetNextState(acsm,r,i);

            if(s != ACSM_FAIL_STATE2 && s!= 0)
            {
                queue_add(queue, s);
            }
            else
            {
                cFailState = List_GetNextState(acsm,FailState[r],i);

                if(cFailState != 0 && cFailState != ACSM_FAIL_STATE2)
                {
                    List_PutNextState(acsm,r,i,cFailState);
                }
            }
        }
    }

    /* Clean up the queue */
    queue_free(queue);

    if(s_verbose)
    {
        ALERT("End Convert_NFA_To_DFA: NumStates=%d\n",acsm->acsmNumStates);
    }

}

/*
*
*  Convert a row lists for the state table to a full vector format
*
*/
static int Conv_List_To_Full(ACSM_STRUCT2 * acsm)
{
    int         tcnt, k;
    acstate_t * p;
    acstate_t ** NextState = acsm->acsmNextState;
    unsigned long long dl_request_size;
    size_t request_size;

    for(k=0; k<acsm->acsmMaxStates; k++)
    {
        {
            dl_request_size = sizeof(acstate_t) *(unsigned long long)(acsm->acsmAlphabetSize+2);

            request_size =(size_t)dl_request_size;
            if(request_size != dl_request_size)
                return -1;
        }
        //ALERT("acsmNextState[%d]\n", k);
        p = AC_MALLOC(request_size);
        if(!p) return -1;

        tcnt = List_ConvToFull(acsm,(acstate_t)k, p+2);

        p[0] = ACF_FULL;
        p[1] = 0; /* no matches yet */

        NextState[k] = p; /* now we have a full format row vector  */
    }

    return 0;
}

/*
*   Convert DFA memory usage from list based storage to a sparse-row storage.
*
*   The Sparse format allows each row to be either full or sparse formatted.  If the sparse row has
*   too many transitions, performance or space may dictate that we use the standard full formatting
*   for the row.  More than 5 or 10 transitions per state ought to really whack performance. So the
*   user can specify the max state transitions per state allowed in the sparse format.
*
*   Standard Full Matrix Format
*   ---------------------------
*   acstate_t ** NextState(1st index is row/state, 2nd index is column=event/input)
*
*   example:
*
*        events -> a b c d e f g h i j k l m n o p
*   states
*     N            1 7 0 0 0 3 0 0 0 0 0 0 0 0 0 0
*
*   Sparse Format, each row : Words     Value
*                            1-1       fmt(0-full,1-sparse,2-banded,3-sparsebands)
*                            2-2       bool match flag(indicates this state has pattern matches)
*                            3-3       sparse state count(# of input/next-state pairs)
*                            4-3+2*cnt 'input,next-state' pairs... each sizof(acstate_t)
*
*   above example case yields:
*     Full Format:    0, 1 7 0 0 0 3 0 0 0 0 0 0 0 0 0 0 ...
*     Sparse format:  1, 3, 'a',1,'b',7,'f',3  - uses 2+2*ntransitions(non-default transitions)
*/
static int Conv_Full_DFA_To_Sparse(ACSM_STRUCT2 * acsm)
{
    int          cnt, m, k, i;
    acstate_t  * p, state, maxstates=0;
    acstate_t ** NextState = acsm->acsmNextState;

    unsigned long long dl_request_size;
    size_t request_size;
    int ret;
    
    acstate_t * full = AC_MALLOC(MAX_ALPHABET_SIZE);
    if (full != NULL)
	{
        goto _Conv_Full_DFA_To_Sparse_END;
	}
    
    for(k=0; k<acsm->acsmMaxStates; k++)
    {
        cnt=0;

        List_ConvToFull(acsm,(acstate_t)k, full);

        for(i = 0; i < acsm->acsmAlphabetSize; i++)
        {
            state = full[i];
            if(state != 0 && state != ACSM_FAIL_STATE2) cnt++;
        }

        if(cnt > 0) maxstates++;

        if(k== 0 || cnt > acsm->acsmSparseMaxRowNodes)
        {
            {
                dl_request_size = sizeof(acstate_t) *(unsigned long long)(acsm->acsmAlphabetSize+2);

                request_size =(size_t)dl_request_size;
                if(request_size != dl_request_size)
                {
                    ret = -1;
                    goto _Conv_Full_DFA_To_Sparse_END;
                }
            }
            p = AC_MALLOC(request_size);
            if(!p)
            {
                ret = -1;
                goto _Conv_Full_DFA_To_Sparse_END;
            }

            p[0] = ACF_FULL;
            p[1] = 0;
            memcpy(&p[2],full,acsm->acsmAlphabetSize*sizeof(acstate_t));
        }
        else
        {
            p = AC_MALLOC(sizeof(acstate_t)*(3+2*cnt));
            if(!p)
            {
                ret = -1;
                goto _Conv_Full_DFA_To_Sparse_END;
            }

            m      = 0;
            p[m++] = ACF_SPARSE;
            p[m++] = 0;   /* no matches */
            p[m++] = cnt;

            for(i = 0; i < acsm->acsmAlphabetSize ; i++)
            {
                state = full[i];
                if(state != 0 && state != ACSM_FAIL_STATE2)
                {
                    p[m++] = i;
                    p[m++] = state;
                }
            }
        }

        NextState[k] = p; /* now we are a sparse formatted state transition array  */
    }
    
_Conv_Full_DFA_To_Sparse_END:
    if (full != NULL)
	{
		AC_FREE(full);
	}
    return 0;
}
/*
    Convert Full matrix to Banded row format.

    Word     values
    1        2  -> banded
    2        n  number of values
    3        i  index of 1st value(0-256)
    4 - 3+n  next-state values at each index

*/
static int Conv_Full_DFA_To_Banded(ACSM_STRUCT2 * acsm)
{
    int first = -1, last;
    acstate_t * p, state, full[MAX_ALPHABET_SIZE];
    acstate_t ** NextState = acsm->acsmNextState;
    int       cnt,m,k,i;

    for(k=0; k<acsm->acsmMaxStates; k++)
    {
        cnt=0;

        List_ConvToFull(acsm,(acstate_t)k, full);

        first=-1;
        last =-2;

        for(i = 0; i < acsm->acsmAlphabetSize; i++)
        {
            state = full[i];

            if(state !=0 && state != ACSM_FAIL_STATE2)
            {
                if(first < 0) first = i;
                last = i;
            }
        }

        /* calc band width */
        cnt= last - first + 1;

        p = AC_MALLOC(sizeof(acstate_t)*(4+cnt));

        if(!p) return -1;

        m      = 0;
        p[m++] = ACF_BANDED;
        p[m++] = 0;   /* no matches */
        p[m++] = cnt;
        p[m++] = first;

        for(i = first; i <= last; i++)
        {
            p[m++] = full[i];
        }

        NextState[k] = p; /* now we are a banded formatted state transition array  */
    }

    return 0;
}

/*
*   Convert full matrix to Sparse Band row format.
*
*   next  - Full formatted row of next states
*   asize - size of alphabet
*   zcnt - max number of zeros in a run of zeros in any given band.
*
*  Word Values
*  1    ACF_SPARSEBANDS
*  2    number of bands
*  repeat 3 - 5+ ....once for each band in this row.
*  3    number of items in this band*  4    start index of this band
*  5-   next-state values in this band...
*/
static int calcSparseBands(acstate_t * next, int * begin, int * end, int asize, int zmax)
{
    int i, nbands,zcnt,last=0;
    acstate_t state;

    nbands=0;
    for(i=0; i<asize; i++)
    {
        state = next[i];
        if(state !=0 && state != ACSM_FAIL_STATE2)
        {
            begin[nbands] = i;
            zcnt=0;
            for(; i< asize; i++)
            {
                state = next[i];
                if(state ==0 || state == ACSM_FAIL_STATE2)
                {
                    zcnt++;
                    if(zcnt > zmax) break;
                }
                else
                {
                    zcnt=0;
                    last = i;
                }
            }
            end[nbands++] = last;
        }
    }
    return nbands;
}


/*
*   Sparse Bands
*
*   Row Format:
*   Word
*   1    SPARSEBANDS format indicator
*   2    bool indicates a pattern match in this state
*   3    number of sparse bands
*   4    number of elements in this band
*   5    start index of this band
*   6-   list of next states
*
*   m    number of elements in this band
*   m+1  start index of this band
*   m+2- list of next states
*/

static int Conv_Full_DFA_To_SparseBands(ACSM_STRUCT2 * acsm)
{
    acstate_t  * p;
    acstate_t ** NextState = acsm->acsmNextState;
    
    int cnt,m,k,i,zcnt=acsm->acsmSparseMaxZcnt;
    int nbands, j;
    int ret = 0;
    
	int * band_begin = AC_MALLOC(MAX_ALPHABET_SIZE);
	int * band_end   = AC_MALLOC(MAX_ALPHABET_SIZE);
	acstate_t * full = AC_MALLOC(MAX_ALPHABET_SIZE);
	
	if (band_begin == NULL || band_end == NULL || full ==NULL)
	{
		goto _CONV_FULL_DFA_TO_SPARSE;
	}

    for (k=0; k<acsm->acsmMaxStates; k++)
    {
        cnt=0;

        List_ConvToFull(acsm,(acstate_t)k, full);

        nbands = calcSparseBands(full, band_begin, band_end, acsm->acsmAlphabetSize, zcnt);

        /* calc band width space*/
        cnt = 3;
        for (i=0; i<nbands; i++)
        {
            cnt += 2;
            cnt += band_end[i] - band_begin[i] + 1;

            /*printf("state %d: sparseband %d,  first=%d, last=%d, cnt=%d\n",k,i,band_begin[i],band_end[i],band_end[i]-band_begin[i]+1); */
        }

        p = AC_MALLOC(sizeof(acstate_t)*(cnt));

        if (!p)
        {
        	ret = -1;
        	goto _CONV_FULL_DFA_TO_SPARSE;
        }

        m      = 0;
        p[m++] = ACF_SPARSEBANDS;
        p[m++] = 0; /* no matches */
        p[m++] = nbands;

        for (i=0; i<nbands; i++)
        {
            p[m++] = band_end[i] - band_begin[i] + 1;  /* # states in this band */
            p[m++] = band_begin[i];   /* start index */

            for (j=band_begin[i]; j<=band_end[i]; j++)
            {
                p[m++] = full[j];  /* some states may be state zero */
            }
        }

        NextState[k] = p; /* now we are a sparse-banded formatted state transition array  */
    }

_CONV_FULL_DFA_TO_SPARSE:

	if (band_begin != NULL)
	{
		AC_FREE(band_begin);
	}
	if (band_end != NULL)
	{
		AC_FREE(band_end);
	}
	if (full != NULL)
	{
		AC_FREE(full);
	}

    return ret;
}

void Print_DFA_MatchList(ACSM_STRUCT2 * acsm, int state)
{
    ACSM_PATTERN2 * mlist;

    for(mlist = acsm->acsmMatchList[state];
            mlist;
            mlist = mlist->next)
    {
        ALERT("%.*s ", mlist->n, mlist->patrn);
    }
}
/*
*
*/
void Print_DFA(ACSM_STRUCT2 * acsm)
{
    int  k,i;
    acstate_t * p, state, n, fmt, index, nb, bmatch;
    acstate_t ** NextState = acsm->acsmNextState;

    ALERT("Print DFA - %d active states\n",acsm->acsmNumStates);

    for(k=0; k<acsm->acsmNumStates; k++)
    {
        p   = NextState[k];

        if(!p) continue;

        fmt = *p++;

        bmatch = *p++;

        ALERT("state %3d, fmt=%d: ",k,fmt);

        if(fmt ==ACF_SPARSE)
        {
            n = *p++;
            for(; n>0; n--, p+=2)
            {
                if(isprint(p[0]))
                {
                    ALERT("%3c->%-5d\t",p[0],p[1]);
                }
                else
                {
                    ALERT("%3d->%-5d\t",p[0],p[1]);
                }
            }
        }
        else if(fmt ==ACF_BANDED)
        {

            n = *p++;
            index = *p++;

            for(; n>0; n--, p++)
            {
                if(isprint(p[0]))
                {
                    ALERT("%3c->%-5d\t",index++,p[0]);
                }
                else
                {
                    ALERT("%3d->%-5d\t",index++,p[0]);
                }
            }
        }
        else if(fmt ==ACF_SPARSEBANDS)
        {
            nb    = *p++;
            for(i=0; i<nb; i++)
            {
                n     = *p++;
                index = *p++;
                for(; n>0; n--, p++)
                {
                    if(isprint(index))
                    {
                        ALERT("%3c->%-5d\t",index++,p[0]);
                    }
                    else
                    {
                        ALERT("%3d->%-5d\t",index++,p[0]);
                    }
                }
            }
        }
        else if(fmt == ACF_FULL)
        {

            for(i=0; i<acsm->acsmAlphabetSize; i++)
            {
                state = p[i];

                if(state != 0 && state != ACSM_FAIL_STATE2)
                {
                    if(isprint(i))
                    {
                        ALERT("%3c->%-5d\t",i,state);
                    }
                    else
                    {
                        ALERT("%3d->%-5d\t",i,state);
                    }
                }
            }
        }

        Print_DFA_MatchList(acsm, k);

        ALERT("\n");
    }
}
/*
*  Write a state table to disk
*/
#if 0
static void Write_DFA(ACSM_STRUCT2 * acsm, char * f)
{
  int  k,i;
  acstate_t * p, n, fmt, index, nb, bmatch;
  acstate_t ** NextState = acsm->acsmNextState;
  FILE * fp;

  ALERT("Dump DFA - %d active states\n",acsm->acsmNumStates);

  fp = fopen(f,"wb");
  if(!fp)
   {
     ALERT("*** WARNING: could not write dfa to file - %s\n",f);
     return;
   }

  fwrite(&acsm->acsmNumStates, 4, 1, fp);

  for(k=0;k<acsm->acsmNumStates;k++)
  {
    p   = NextState[k];

    if(!p) continue;

    fmt = *p++;

    bmatch = *p++;

    fwrite(&fmt,    sizeof(acstate_t), 1, fp);
    fwrite(&bmatch, sizeof(acstate_t), 1, fp);

    if(fmt ==ACF_SPARSE)
    {
       n = *p++;
       fwrite(&n,     sizeof(acstate_t), 1, fp);
       fwrite( p, n*2*sizeof(acstate_t), 1, fp);
    }
    else if(fmt ==ACF_BANDED)
    {
       n = *p++;
       fwrite(&n,     sizeof(acstate_t), 1, fp);

       index = *p++;
       fwrite(&index, sizeof(acstate_t), 1, fp);

       fwrite( p, sizeof(acstate_t), n, fp);
    }
    else if(fmt ==ACF_SPARSEBANDS)
    {
       nb    = *p++;
       fwrite(&nb,    sizeof(acstate_t), 1, fp);
       for(i=0;i<nb;i++)
       {
         n     = *p++;
         fwrite(&n,    sizeof(acstate_t), 1, fp);

         index = *p++;
         fwrite(&index,sizeof(acstate_t), 1, fp);

         fwrite(p,     sizeof(acstate_t), 1, fp);
       }
    }
    else if(fmt == ACF_FULL)
    {
      fwrite(p,  sizeof(acstate_t), acsm->acsmAlphabetSize,  fp);
    }

    Print_DFA_MatchList(acsm, k);

  }

  fclose(fp);
}
#endif

/*
*
*   Convert an NFA or DFA row from sparse to full format
*   and store into the 'full'  buffer.
*
*   returns:
*     0 - failed, no state transitions
*    *p - pointer to 'full' buffer
*
*/
/*
static acstate_t * acsmConvToFull(ACSM_STRUCT2 * acsm, acstate_t k, acstate_t * full)
{
    int i;
    acstate_t * p, n, fmt, index, nb, bmatch;
    acstate_t ** NextState = acsm->acsmNextState;

    p   = NextState[k];

    if(!p) return 0;

    fmt = *p++;

    bmatch = *p++;

    if(fmt ==ACF_SPARSE)
    {
       n = *p++;
       for(; n>0; n--, p+=2)
       {
         full[ p[0] ] = p[1];
      }
    }
    else if(fmt ==ACF_BANDED)
    {

       n = *p++;
       index = *p++;

       for(; n>0; n--, p++)
       {
         full[ index++ ] = p[0];
      }
    }
    else if(fmt ==ACF_SPARSEBANDS)
    {
       nb    = *p++;
       for(i=0;i<nb;i++)
       {
         n     = *p++;
         index = *p++;
         for(; n>0; n--, p++)
         {
           full[ index++ ] = p[0];
         }
       }
    }
    else if(fmt == ACF_FULL)
    {
      memcpy(full,p,acsm->acsmAlphabetSize*sizeof(acstate_t));
    }

    return full;
}
*/

/*
*   Select the desired storage mode
*/
int acsmSelectFormat2(ACSM_STRUCT2 * acsm, int m)
{
    switch(m)
    {
    case ACF_FULL:
    case ACF_SPARSE:
    case ACF_BANDED:
    case ACF_SPARSEBANDS:
        acsm->acsmFormat = m;
        break;
    default:
        return -1;
    }

    return 0;
}
/*
*
*/
void acsmSetMaxSparseBandZeros2(ACSM_STRUCT2 * acsm, int n)
{
    acsm->acsmSparseMaxZcnt = n;
}
/*
*
*/
void acsmSetMaxSparseElements2(ACSM_STRUCT2 * acsm, int n)
{
    acsm->acsmSparseMaxRowNodes = n;
}
/*
*
*/
int acsmSelectFSA2(ACSM_STRUCT2 * acsm, int m)
{
    switch(m)
    {
    case FSA_TRIE:
    case FSA_NFA:
    case FSA_DFA:
        acsm->acsmFSA = m;
    default:
        return -1;
    }
}
/*
*
*/
int acsmSetAlphabetSize2(ACSM_STRUCT2 * acsm, int n)
{
    if(n <= MAX_ALPHABET_SIZE)
    {
        acsm->acsmAlphabetSize = n;
    }
    else
    {
        return -1;
    }
    return 0;
}


////////////////////////////////////////////////////////////////////////////////
/*
*  Create a new AC state machine 初始化一个AC状态机 也就是ACSM_STRUCT2
*/
ACSM_STRUCT2 * acsmNew2(void)
{
    ACSM_STRUCT2 * p;

    init_xlatcase();

    /* AC_MALLOC已经被替换成了当前设备使用的malloc版本 */
    p =(ACSM_STRUCT2 *) AC_MALLOC(sizeof(ACSM_STRUCT2));
    MEMASSERT1(p, "acsmNew");

    if(p)
    {
        memset(p, 0, sizeof(ACSM_STRUCT2));

        /* Some defaults 给状态机结构体赋初始值 */
        p->acsmFSA               = FSA_DFA;
        p->acsmFormat            = ACF_FULL;//ACF_BANDED;
        p->acsmAlphabetSize      = 256;
        p->acsmSparseMaxRowNodes = 256;
        p->acsmSparseMaxZcnt     = 10;
        spin_lock_init(&p->lock_acsmMatchList);
    }

    return p;
}
///////////////////////////////////////acsmAddPattern2//////////////////////////
#if 0
/* 此结构由自己定义，没有此结构也没关系 */
typedef struct
{
    /*pattern*/
    char * pattern;      //模式，就是字符串
    /*pattern length*/
    int   plen;          //模式长度 
    /*pattern text case*/
    int   nocase;        //是否区分大小写
    /*offset from last matched*/
    int   offset;        //上次匹配到该模式的偏移量
    /*searching leng from offset*/ /*check 时看他的位置*/
    int   depth;         //((pat->offset <= index) &&(index <= pat->depth))
    /*pattern id*/
    int   patid;
} parser_prepare_key_t;
static parser_prepare_key_t _parser_prepare_keys[]=
{
    //pattern,plen,nocase,offset,depth,patid
    {"POST ", 5,   1,     0,     0,    HTTP_POST},
    {"GET ",  4,   1,     0,     0,    HTTP_GET},
};
key = &_parser_prepare_keys[i];
ret = acsmAddPattern2(_pdesc_petreat_keys_pmse->obj,
                      (unsigned char *)key->pattern,(int)key->plen,
                      (int)key->nocase,(int)key->offset,(int)key->depth,
                      (void *)key,(int)key->patid);
#endif
/*
*   Add a pattern to the list of patterns for this state machine
*   将一个模式添加到AC状态机的模式链表内, 第一个参数p是一个指向AC状态机结构体的指针
*   结合ACSM_PATTERN2、parser_prepare_key_t和这几个参数是如何调用的，看看每个成员都是什么含义
*   在外部定义的parser_prepare_key_t其实传递到AC模块后使用的是ACSM_PATTERN2链表
*/
int acsmAddPattern2(ACSM_STRUCT2 * p,
                    unsigned char * pat, // 关键字
                    int n,               // 关键字长度
                    int nocase,          // 是否关系大小写
                    int offset,          // 搜索偏移量
                    int depth,           // 搜索长度
                    void * id,           // 为关键字结构体的指针(parser_prepare_key_t)
                    int iid)             // 关键字id
{

    ACSM_PATTERN2 * plist;
    if(p == NULL)
    {
        return -1;
    }
    if(n < 0)
    {
        return -1;
    }

    plist =(ACSM_PATTERN2 *)AC_MALLOC(sizeof(ACSM_PATTERN2));
    MEMASSERT2(plist, "acsmAddPattern error ACSM_PATTERN2");

    plist->patrn =(unsigned char *)AC_MALLOC(n);
    if(!plist->patrn)
    {
        AC_FREE(plist);
        MEMASSERT2(plist->patrn, "acsmAddPattern error patrn");
    }

    ConvertCaseEx(plist->patrn, pat, n); //全部被转成大写 

    plist->casepatrn =(unsigned char *)AC_MALLOC(n);
    if(!plist->casepatrn)
    {
        AC_FREE(plist->patrn);
        AC_FREE(plist);
        MEMASSERT2(plist->casepatrn, "acsmAddPattern error casepatrn");
    }

    memcpy(plist->casepatrn, pat, n);   //保留了原始字符 
    plist->n      = n;
    plist->nocase = nocase;
    plist->offset = offset;
    plist->depth  = depth;
    plist->id     = id;     //传递给其值的key结构，即原始模式，其实就是你自己手工定义的结构标识符，
    //当匹配到该模式时能找到你自己手工定义的那个模式
    plist->iid    = iid;    //模式id

    plist->next     = p->acsmPatterns; //在AC状态机结构和模式链表之间插入该节点
    p->acsmPatterns = plist;

    return 0;
}
/*
*   Add a Key to the list of key+data pairs
*/
int acsmAddKey2(ACSM_STRUCT2 * p, unsigned char *key, int klen, int nocase, void * data)
{
    ACSM_PATTERN2 * plist;

    plist =(ACSM_PATTERN2 *)AC_MALLOC(sizeof(ACSM_PATTERN2));
    MEMASSERT2(plist, "acsmAddPattern");

    plist->patrn =(unsigned char *)AC_MALLOC(klen);
    memcpy(plist->patrn, key, klen);

    plist->casepatrn =(unsigned char *)AC_MALLOC(klen);
    memcpy(plist->casepatrn, key, klen);

    plist->n      = klen;
    plist->nocase = nocase;
    plist->offset = 0;
    plist->depth  = 0;
    plist->id     = 0;
    plist->iid = 0;

    plist->next = p->acsmPatterns;
    p->acsmPatterns = plist;

    return 0;
}

/*
*  Copy a boolean match flag int NextState table, for caching purposes.
*/
static void acsmUpdateMatchStates(ACSM_STRUCT2 * acsm)
{
    acstate_t        state;
    acstate_t     ** NextState = acsm->acsmNextState;
    ACSM_PATTERN2 ** MatchList = acsm->acsmMatchList;

    for(state=0; state<acsm->acsmNumStates; state++)
    {
        if(MatchList[state])
        {
            NextState[state][1] = 1;
        }
        else
        {
            NextState[state][1] = 0;
        }
    }
}

/*
*   Compile State Machine - NFA or DFA and Full or Banded or Sparse or SparseBands
*   对AC关键字链表进行编译，参数是状态机结构指针，真正有技术含量的地方
*/
int acsmCompile2(ACSM_STRUCT2 * acsm)
{
    int               k;
    ACSM_PATTERN2    * plist;

    /* Count number of states 通过模式个数计算状态个数，其实在acsmAddPattern2的时候计算更省一些 */
    for(plist = acsm->acsmPatterns; plist != NULL; plist = plist->next)
    {
        acsm->acsmMaxStates += plist->n;
        /* acsm->acsmMaxStates += plist->n*2; // 如果关心大小写就得是当前大小的两倍 if we handle case in the table */
    }
    acsm->acsmMaxStates++; /* one extra 如果没有子串存在，这样保证了有足够的空间存储所有状态，其中一个是0初始状态，但其实应该用不了这么多 */

    /* Alloc a List based State Transition table 给状态转换表申请空间，其实是个指针数组  */
    acsm->acsmTransTable = (trans_node_t**)AC_MALLOC(sizeof(trans_node_t*) * acsm->acsmMaxStates);
    MEMASSERT2(acsm->acsmTransTable, "acsmCompile");

    memset(acsm->acsmTransTable, 0, sizeof(trans_node_t*) * acsm->acsmMaxStates);

    if(s_verbose)
    {
        ALERT("ACSMX-Max Memory-TransTable Setup: %zd bytes, %d states, %d active states\n", max_memory,acsm->acsmMaxStates,acsm->acsmNumStates);
    }

    /* Alloc a failure table（失败状态转换表） - this has a failure state, and a match list for each state */
    acsm->acsmFailState =(acstate_t*) AC_MALLOC(sizeof(acstate_t) * acsm->acsmMaxStates);
    if(!acsm->acsmFailState)
    {
        AC_FREE(acsm->acsmTransTable);
        MEMASSERT2(acsm->acsmFailState, "acsmCompile");
    }

    memset(acsm->acsmFailState, 0, sizeof(acstate_t) * acsm->acsmMaxStates);

    /* Alloc a MatchList table（输出表，即匹配成功表） - this has a list of pattern matches for each state, if any */
    acsm->acsmMatchList=(ACSM_PATTERN2**) AC_MALLOC(sizeof(ACSM_PATTERN2*) * acsm->acsmMaxStates);
    if(!acsm->acsmMatchList)
    {
        AC_FREE(acsm->acsmTransTable);
        AC_FREE(acsm->acsmFailState);
        MEMASSERT2(acsm->acsmMatchList, "acsmCompile");
    }

    memset(acsm->acsmMatchList, 0, sizeof(ACSM_PATTERN2*) * acsm->acsmMaxStates);

    if(s_verbose)
    {
        ALERT("ACSMX-Max Memory- MatchList Table Setup: %zd bytes, %d states, %d active states\n",
               max_memory,acsm->acsmMaxStates,acsm->acsmNumStates);
    }

    /* Alloc a separate state transition table （也是一个状态转换表）
       == in state 's' due to event 'k', transition to 'next' state */
    acsm->acsmNextState=(acstate_t**)AC_MALLOC(acsm->acsmMaxStates * sizeof(acstate_t*));
    if(!acsm->acsmNextState)
    {
        AC_FREE(acsm->acsmTransTable);
        AC_FREE(acsm->acsmFailState);
        AC_FREE(acsm->acsmMatchList);
        MEMASSERT2(acsm->acsmNextState, "acsmCompile-NextState");
    }

    for(k = 0; k < acsm->acsmMaxStates; k++)
    {
        acsm->acsmNextState[k]=(acstate_t*)0; // 其初始值都是0，即匹配失败状态都转换为0状态
    }

    if(s_verbose)
    {
        ALERT("ACSMX-Max Memory-Table Setup: %zd bytes, %d states, %d active states\n", 
               max_memory,acsm->acsmMaxStates,acsm->acsmNumStates);
    }

    //////////////////////////////////////////////////////////////////////////////////
    ///
    ///  上面都是申请空间，下面开始初始化状态机
    ///
    //////////////////////////////////////////////////////////////////////////////////
    
    /* Initialize state zero as a branch 当前状态机的状态是0 */
    acsm->acsmNumStates = 0;

    /* Add the 0'th state,  */
    //acsm->acsmNumStates++;

    /* 
       将状态机内的关键字进行状态转换的编译
       Add each Pattern to the State Table - This forms a keywords state table  */
    for(plist = acsm->acsmPatterns; plist != NULL; plist = plist->next)
    {
        AddPatternStates(acsm, plist);
    }

    acsm->acsmNumStates++;

    if(s_verbose)
    {
        ALERT("ACSMX-Max Trie List Memory : %zd bytes, %d states, %d active states\n",
                 max_memory,acsm->acsmMaxStates,acsm->acsmNumStates);
    }
    if(s_verbose)
    {
        List_PrintTransTable(acsm);
    }

    if(acsm->acsmFSA == FSA_DFA || acsm->acsmFSA == FSA_NFA)
    {
        /* Build the NFA */
        if(s_verbose)
        {
            ALERT("Build_NFA\n");
        }

        Build_NFA(acsm);

        if(s_verbose)
        {
            ALERT("NFA-Trans-Nodes: %d\n",acsm->acsmNumTrans);
        }
        if(s_verbose)
        {
            ALERT("ACSMX-Max NFA List Memory  : %zd bytes, %d states / %d active states\n", max_memory,acsm->acsmMaxStates,acsm->acsmNumStates);
        }

        if(s_verbose)
        {
            List_PrintTransTable(acsm);
        }
    }

    if(acsm->acsmFSA == FSA_DFA)
    {
        /* Convert the NFA to a DFA */
        if(s_verbose)
        {
            ALERT("Convert_NFA_To_DFA\n");
        }

        Convert_NFA_To_DFA(acsm);

        if(s_verbose)
        {
            ALERT("DFA-Trans-Nodes: %d\n",acsm->acsmNumTrans);
        }
        if(s_verbose)
        {
            ALERT("ACSMX-Max NFA-DFA List Memory  : %zd bytes, %d states / %d active states\n", max_memory,acsm->acsmMaxStates,acsm->acsmNumStates);
        }

        if(s_verbose)
        {
            List_PrintTransTable(acsm);
        }
    }

    /*
    *
    *  Select Final Transition Table Storage Mode
    *
    */

    if(s_verbose)
    {
        ALERT("Converting Transition Lists -> Transition table, fmt=%d\n",acsm->acsmFormat);
    }

    if(acsm->acsmFormat == ACF_SPARSE)
    {
        /* Convert DFA Full matrix to a Sparse matrix */
        if(Conv_Full_DFA_To_Sparse(acsm))
            return -1;

        if(s_verbose)
        {
            ALERT("ACSMX-Max Memory-Sparse: %zd bytes, %d states, %d active states\n", max_memory,acsm->acsmMaxStates,acsm->acsmNumStates);
        }
        if(s_verbose)Print_DFA(acsm);
    }

    else if(acsm->acsmFormat == ACF_BANDED)
    {
        /* Convert DFA Full matrix to a Sparse matrix */
        if(Conv_Full_DFA_To_Banded(acsm))
            return -1;

        if(s_verbose)
        {
            ALERT("ACSMX-Max Memory-banded: %zd bytes, %d states, %d active states\n", max_memory,acsm->acsmMaxStates,acsm->acsmNumStates);
        }
        if(s_verbose)Print_DFA(acsm);
    }

    else if(acsm->acsmFormat == ACF_SPARSEBANDS)
    {
        /* Convert DFA Full matrix to a Sparse matrix */
        if(Conv_Full_DFA_To_SparseBands(acsm))
            return -1;

        if(s_verbose)
        {
            ALERT("ACSMX-Max Memory-sparse-bands: %zd bytes, %d states, %d active states\n", max_memory,acsm->acsmMaxStates,acsm->acsmNumStates);
        }
        if(s_verbose)Print_DFA(acsm);
    }
    else if(acsm->acsmFormat == ACF_FULL)
    {
        if(Conv_List_To_Full(acsm))
            return -1;

        if(s_verbose)
        {
            ALERT("ACSMX-Max Memory-Full: %zd bytes, %d states, %d active states\n", max_memory,acsm->acsmMaxStates,acsm->acsmNumStates);
        }
        if(s_verbose)Print_DFA(acsm);
    }

    acsmUpdateMatchStates(acsm); /* load boolean match flags into state table */

    /* Free up the Table Of Transition Lists */
    List_FreeTransTable(acsm);

    if(s_verbose)
    {
        ALERT("ACSMX-Max Memory-Final: %zd bytes, %d states, %d active states\n", max_memory,acsm->acsmMaxStates,acsm->acsmNumStates);
    }

    /* For now -- show this info */
    /*
    *  acsmPrintInfo(acsm);
    */


    /* Accrue Summary State Stats */
    summary.num_states      += acsm->acsmNumStates;
    summary.num_transitions += acsm->acsmNumTrans;

    memcpy(&summary.acsm, acsm, sizeof(ACSM_STRUCT2));

    return 0;
}

/*
*   Get the NextState from the NFA, all NFA storage formats use this
*/
inline acstate_t SparseGetNextStateNFA(acstate_t * ps, acstate_t state, unsigned  input)
{
    acstate_t fmt;
    acstate_t n;
    unsigned int       index;
    int       nb;

    fmt = *ps++;

    ps++;  /* skip bMatchState */

    switch(fmt)
    {
    case  ACF_BANDED:
    {
        n     = ps[0];
        index = ps[1];

        if(input < index)
        {
            if(state==0)
            {
                return 0;
            }
            else
            {
                return(acstate_t)ACSM_FAIL_STATE2;
            }
        }
        if(input >= index + n)
        {
            if(state==0)
            {
                return 0;
            }
            else
            {
                return(acstate_t)ACSM_FAIL_STATE2;
            }
        }
        if(ps[input-index] == 0 )
        {
            if(state != 0)
            {
                return ACSM_FAIL_STATE2;
            }
        }

        return(acstate_t) ps[input-index];
    }

    case ACF_SPARSE:
    {
        n = *ps++; /* number of sparse index-value entries */

        for(; n>0 ; n--)
        {
            if(ps[0] > input) /* cannot match the input, already a higher value than the input  */
            {
                return(acstate_t)ACSM_FAIL_STATE2; /* default state */
            }
            else if(ps[0] == input)
            {
                return ps[1]; /* next state */
            }
            ps+=2;
        }
        if(state == 0)
        {
            return 0;
        }
        return ACSM_FAIL_STATE2;
    }

    case ACF_SPARSEBANDS:
    {
        nb  = *ps++;   /* number of bands */

        while(nb > 0)  /* for each band */
        {
            n     = *ps++;  /* number of elements */
            index = *ps++;  /* 1st element value */

            if(input < index)
            {
                if(state != 0)
                {
                    return(acstate_t)ACSM_FAIL_STATE2;
                }
                return(acstate_t)0;
            }
            if((input >= index) &&(input <(index + n)))
            {
                if(ps[input-index] == 0)
                {
                    if(state != 0)
                    {
                        return ACSM_FAIL_STATE2;
                    }
                }
                return(acstate_t) ps[input-index];
            }
            nb--;
            ps += n;
        }
        if(state != 0)
        {
            return(acstate_t)ACSM_FAIL_STATE2;
        }
        return(acstate_t)0;
    }

    case ACF_FULL:
    {
        if(ps[input] == 0)
        {
            if(state != 0)
            {
                return ACSM_FAIL_STATE2;
            }
        }
        return ps[input];
    }
    }

    return 0;
}



/*
*   Get the NextState from the DFA Next State Transition table
*   Full and banded are supported separately, this is for
*   sparse and sparse-bands
*/
inline acstate_t SparseGetNextStateDFA(acstate_t * ps, acstate_t state, unsigned  input)
{
    acstate_t  n, nb;
    unsigned int index;

    switch(ps[0])
    {
        /*   BANDED   */
	    case  ACF_BANDED:
	    {
	        /* n=ps[2] : number of entries in the band */
	        /* index=ps[3] : index of the 1st entry, sequential thereafter */

	        if(input < ps[3]) return 0;
	        if(input >=(unsigned)(ps[3]+ps[2])) return 0;

	        return  ps[4+input-ps[3]];
	    }

	    /*   FULL   */
	    case ACF_FULL:
	    {
	        return ps[2+input];
	    }

	    /*   SPARSE   */
	    case ACF_SPARSE:
	    {
	        n = ps[2]; /* number of entries/ key+next pairs */

	        ps += 3;

	        for(; n>0 ; n--)
	        {
	            if(input < ps[0]) /* cannot match the input, already a higher value than the input  */
	            {
	                return(acstate_t)0; /* default state */
	            }
	            else if(ps[0] == input)
	            {
	                return ps[1]; /* next state */
	            }
	            ps += 2;
	        }
	        return(acstate_t)0;
	    }


	    /*   SPARSEBANDS   */
	    case ACF_SPARSEBANDS:
	    {
	        nb  =  ps[2]; /* number of bands */

	        ps += 3;

	        while(nb > 0)  /* for each band */
	        {
	            n     = ps[0];  /* number of elements in this band */
	            index = ps[1];  /* start index/char of this band */
	            if(input < index)
	            {
	                return(acstate_t)0;
	            }
	            if((input < (index + n)))
	            {
	                return(acstate_t) ps[2+input-index];
	            }
	            nb--;
	            ps += 2 + n;
	        }
	        return(acstate_t)0;
	    }
    }

    return 0;
}

/*
*   Full format DFA search
*   Do not change anything here without testing, caching and prefetching
*   performance is very sensitive to any changes.
*
*   Perf-Notes:
*    1) replaced ConvertCaseEx with inline xlatcase - this improves performance 5-10%
*    2) using 'nocase' improves performance again by 10-15%, since memcmp is not needed
*    3)
*/
static inline int acsmSearchSparseDFA_Full(ACSM_STRUCT2 * acsm, unsigned char *Tx, int n,
        int(*Match)(void * id, int index, void *data,void*arg),
        void *data,void *arg)
{
    ACSM_PATTERN2   * mlist;
    unsigned char   * Tend;
    unsigned char   * T;
    int               index;
    acstate_t         state;
    acstate_t       * ps;
    acstate_t         sindex;
    acstate_t      ** NextState = acsm->acsmNextState;
    ACSM_PATTERN2  ** MatchList = acsm->acsmMatchList;
    int               nfound    = 0;

    T    = Tx;
    Tend = Tx + n;

    //printf("T = %x %x %x %x,acsmMaxStates = %d\n",T[0],T[1],T[2],T[3],acsm->acsmMaxStates);

    for(state = 0; T < Tend; T++)
    {
        ps     = NextState[ state ];

        sindex = xlatcase[ T[0] ];

        //  printf("state = %d,sindex = %d\n",state,sindex);


        /* check the current state for a pattern match */
        if(ps[1])
        {
            for(mlist = MatchList[state];
                    mlist!= NULL;
                    mlist = mlist->next)
            {
                index = T - mlist->n - Tx;

                if(mlist->nocase)
                {
                    //nfound++;
                    if(Match(mlist->id, index, data,arg))
                        //return nfound;
                        nfound++;
                }
                else
                {
                    if(memcmp(mlist->casepatrn, Tx + index, mlist->n) == 0)
                    {
                        //nfound++;
                        if(Match(mlist->id, index, data,arg))
                            //return nfound;
                            nfound++;
                    }
                }
            }
        }

        state = ps[ 2u + sindex ];
    }

    /* Check the last state for a pattern match */
    for(mlist = MatchList[state];
            mlist!= NULL;
            mlist = mlist->next)
    {
        index = T - mlist->n - Tx;

        if(mlist->nocase)
        {
            //nfound++;
            if(Match(mlist->id, index, data,arg))
                //return nfound;
                nfound++;
        }
        else
        {
            if(memcmp(mlist->casepatrn, Tx + index, mlist->n) == 0)
            {
                //nfound++;
                if(Match(mlist->id, index, data,arg))
                    //return nfound;
                    nfound++;
            }
        }
    }

    return nfound;
}

/*
*   Full format DFA search
*   Do not change anything here without testing, caching and prefetching
*   performance is very sensitive to any changes.
*
*   Perf-Notes:
*    1) replaced ConvertCaseEx with inline xlatcase - this improves performance 5-10%
*    2) using 'nocase' improves performance again by 10-15%, since memcmp is not needed
*    3)
*/
#if 0
int acsmSearchSparseDFA_Full_2(ACSM_STRUCT2 * acsm, unsigned char **Tx, int n,
                               int(*Match)(void * id, int index, void *data),
                               void *data)
{
    ACSM_PATTERN2   * mlist;
    unsigned char   * Tend;
    unsigned char   * T;//oT;
    int               index;
    acstate_t         state;
    acstate_t       * ps;
    acstate_t         sindex;
    acstate_t      ** NextState = acsm->acsmNextState;
    ACSM_PATTERN2  ** MatchList = acsm->acsmMatchList;
    //int               nfound    = 0;

    T    = *Tx;//oT = *Tx;
    Tend = *Tx + n;

    for(state = 0; T < Tend; T++)
    {
        ps     = NextState[ state ];

        sindex = xlatcase[ T[0] ];

        /* check the current state for a pattern match */
        if(ps[1])
        {
            for(mlist = MatchList[state];
                    mlist!= NULL;
                    mlist = mlist->next)
            {
                index = T - mlist->n - *Tx;

                if(mlist->nocase)
                {

                    if(Match(mlist->id, index, data))
                    {
                        //*Tx = T;
                        return mlist->iid;
                        //nfound = acsmSearch2((ACSM_STRUCT2 *)((MPSE *)PD_PMSE[PMSE_HOST])->obj, T,n,Match,data);
                    }

                }
                else
                {
                    if(memcmp(mlist->casepatrn, *Tx + index, mlist->n) == 0)
                    {
                        if(Match(mlist->id, index, data))
                        {
                            // *Tx = T;
                            return mlist->iid;
                        }
                    }
                }
            }
        }

        state = ps[ 2u + sindex ];
    }

    /* Check the last state for a pattern match */
    for(mlist = MatchList[state];
            mlist!= NULL;
            mlist = mlist->next)
    {
        index = T - mlist->n - *Tx;

        if(mlist->nocase)
        {

            if(Match(mlist->id, index, data))
            {
                //*Tx = T;
                return mlist->iid;
            }

        }
        else
        {
            if(memcmp(mlist->casepatrn, *Tx + index, mlist->n) == 0)
            {

                if(Match(mlist->id, index, data))
                {
                    //*Tx = T;
                    return mlist->iid;
                }

            }
        }
    }

    //*Tx = T;
    return -1;
}
#endif

/*
*   Full format DFA search
*   Do not change anything here without testing, caching and prefetching
*   performance is very sensitive to any changes.
*
*   Perf-Notes:
*    1) replaced ConvertCaseEx with inline xlatcase - this improves performance 5-10%
*    2) using 'nocase' improves performance again by 10-15%, since memcmp is not needed
*    3)
*/
int acsmSearchSparseDFA_Full_3(ACSM_STRUCT2 * acsm, unsigned char * Tx, int n,
                               acsm_search_info_t * acsm_search_info,
                               int(* Match)(void * id, int offset, void * data, void * arg),
                               void * data, void * arg)
{
    ACSM_PATTERN2   * mlist;
    unsigned char   * Tend;
    unsigned char   * T;
    int               offset;
    acstate_t       * state = (acstate_t *)&acsm_search_info->state; 
    acstate_t       * ps;
    acstate_t         sindex;
    acstate_t      ** NextState = acsm->acsmNextState;
    ACSM_PATTERN2  ** MatchList = acsm->acsmMatchList;
    int               nfound    = 0;
    int i = 0;
    
    T    = Tx;
    Tend = Tx + n;
    
    ALERT("T = %.*s, n : %d, priv_state = %d, acsmMaxStates = %d\n",  n, T, n, *state, acsm->acsmMaxStates); 

    for(; T < Tend; T++)
    {
        i++;
        ps     = NextState[*state]; 

        sindex = xlatcase[ T[0] ];

        ALERT("ps: %p, ps[1]: %d, *ps: %d, T: %c, i: %d, state: %d\n", ps, ps[1], *ps, T[0], i, *state);
        //ALERT("state = %d, sindex = %d\n",*state,sindex);

        /* check the current state for a pattern match */
        if(ps[1])
        {
            for(mlist = MatchList[*state]; mlist!= NULL; mlist = mlist->next)
            {
                offset = T - mlist->n - Tx;

                if(mlist->nocase)
                {
                    if(Match(mlist->id, offset, data, arg))
                    {
                        nfound++;
                    }
                }
                else
                {
                    if(memcmp(mlist->casepatrn, Tx + offset, mlist->n) == 0)
                    {
                        if(Match(mlist->id, offset, data, arg))
                        {
                            nfound++;
                        }
                    }
                }
            }
        }

        spin_lock(&acsm_search_info->lock);
        *state = ps[ 2u + sindex ];
        spin_unlock(&acsm_search_info->lock);
    }

    /* Check the last state for a pattern match */
    for(mlist = MatchList[*state]; mlist!= NULL; mlist = mlist->next)
    {
        offset = T - mlist->n - Tx;

        if(mlist->nocase)
        {
            if(Match(mlist->id, offset, data, arg))
            {
                nfound++;
            }
        }
        else
        {
            if(memcmp(mlist->casepatrn, Tx + offset, mlist->n) == 0)
            {
                if(Match(mlist->id, offset, data, arg))
                {
                    nfound++;
                }
            }
        }
    }
    spin_lock(&acsm_search_info->lock);
    acsm_search_info->count = nfound;
    spin_unlock(&acsm_search_info->lock);
    return nfound;
}

#if 0
/*
*   Search Text or Binary Data for Pattern matches
*
*   Sparse & Sparse-Banded Matrix search
*/
static inline int acsmSearchSparseDFA(ACSM_STRUCT2 * acsm, unsigned char *Tx, int n,
                                      int(*Match)(void * id, int index, void *data),
                                      void *data)
{
    acstate_t state;
    ACSM_PATTERN2   * mlist;
    unsigned char   * Tend;
    int               nfound = 0;
    unsigned char   * T, * Tc;
    int               index;
    acstate_t      ** NextState = acsm->acsmNextState;
    ACSM_PATTERN2  ** MatchList = acsm->acsmMatchList;

    Tc   = Tx;
    T    = Tx;
    Tend = T + n;

    for(state = 0; T < Tend; T++)
    {
        state = SparseGetNextStateDFA(NextState[state], state, xlatcase[*T]);

        /* test if this state has any matching patterns */
        if(NextState[state][1])
        {
            for(mlist = MatchList[state];
                    mlist!= NULL;
                    mlist = mlist->next)
            {
                index = T - mlist->n - Tc + 1;
                if(mlist->nocase)
                {
                    nfound++;
                    if(Match(mlist->id, index, data))
                        return nfound;
                }
                else
                {
                    if(memcmp(mlist->casepatrn, Tx + index, mlist->n) == 0)
                    {
                        nfound++;
                        if(Match(mlist->id, index, data))
                            return nfound;
                    }
                }
            }
        }
    }
    return nfound;
}



/*
*   Banded-Row format DFA search
*   Do not change anything here, caching and prefetching
*   performance is very sensitive to any changes.
*
*   ps[0] = storage fmt
*   ps[1] = bool match flag
*   ps[2] = # elements in band
*   ps[3] = index of 1st element
*/
static
inline
int
acsmSearchSparseDFA_Banded(ACSM_STRUCT2 * acsm, unsigned char *Tx, int n,
                           int(*Match)(void * id, int index, void *data),
                           void *data)
{
    acstate_t         state;
    unsigned char   * Tend;
    unsigned char   * T;
    int               sindex;
    int               index;
    acstate_t      ** NextState = acsm->acsmNextState;
    ACSM_PATTERN2  ** MatchList = acsm->acsmMatchList;
    ACSM_PATTERN2   * mlist;
    acstate_t       * ps;
    int               nfound = 0;

    T    = Tx;
    Tend = T + n;

    for(state = 0; T < Tend; T++)
    {
        ps     = NextState[state];

        sindex = xlatcase[ T[0] ];

        /* test if this state has any matching patterns */
        if(ps[1])
        {
            for(mlist = MatchList[state];
                    mlist!= NULL;
                    mlist = mlist->next)
            {
                index = T - mlist->n - Tx;

                if(mlist->nocase)
                {
                    nfound++;
                    if(Match(mlist->id, index, data))
                        return nfound;
                }
                else
                {
                    if(memcmp(mlist->casepatrn, Tx + index, mlist->n) == 0)
                    {
                        nfound++;
                        if(Match(mlist->id, index, data))
                            return nfound;
                    }
                }
            }
        }

        if(     sindex <   ps[3]         )  state = 0;
        else if(sindex >=(ps[3] + ps[2]))  state = 0;
        else                                  state = ps[ 4u + sindex - ps[3] ];
    }

    /* Check the last state for a pattern match */
    for(mlist = MatchList[state];
            mlist!= NULL;
            mlist = mlist->next)
    {
        index = T - mlist->n - Tx;

        if(mlist->nocase)
        {
            nfound++;
            if(Match(mlist->id, index, data))
                return nfound;
        }
        else
        {
            if(memcmp(mlist->casepatrn, Tx + index, mlist->n) == 0)
            {
                nfound++;
                if(Match(mlist->id, index, data))
                    return nfound;
            }
        }
    }

    return nfound;
}



/*
*   Search Text or Binary Data for Pattern matches
*
*   Sparse Storage Version
*/
static
inline
int
acsmSearchSparseNFA(ACSM_STRUCT2 * acsm, unsigned char *Tx, int n,
                    int(*Match)(void * id, int index, void *data),
                    void *data)
{
    acstate_t         state;
    ACSM_PATTERN2   * mlist;
    unsigned char   * Tend;
    int               nfound = 0;
    unsigned char   * T, *Tc;
    int               index;
    acstate_t      ** NextState= acsm->acsmNextState;
    acstate_t       * FailState= acsm->acsmFailState;
    ACSM_PATTERN2  ** MatchList = acsm->acsmMatchList;
    unsigned char     Tchar;

    Tc   = Tx;
    T    = Tx;
    Tend = T + n;

    for(state = 0; T < Tend; T++)
    {
        acstate_t nstate;

        Tchar = xlatcase[ *T ];

        while((nstate=SparseGetNextStateNFA(NextState[state],state,Tchar))==ACSM_FAIL_STATE2)
            state = FailState[state];

        state = nstate;

        for(mlist = MatchList[state];
                mlist!= NULL;
                mlist = mlist->next)
        {
            index = T - mlist->n - Tx;
            if(mlist->nocase)
            {
                nfound++;
                if(Match(mlist->id, index, data))
                    return nfound;
            }
            else
            {
                if(memcmp(mlist->casepatrn, Tx + index, mlist->n) == 0)
                {
                    nfound++;
                    if(Match(mlist->id, index, data))
                        return nfound;
                }
            }
        }
    }

    return nfound;
}
#endif
/*
*   Search Function
*/
int acsmSearch2(ACSM_STRUCT2 * acsm, unsigned char *Tx, int n,int(*Match)(void * id, int index, void *data,void *arg),void *data,void *arg)
{
    switch(acsm->acsmFSA)
    {
    case FSA_DFA:

        if(acsm->acsmFormat == ACF_FULL)
        {
            return acsmSearchSparseDFA_Full(acsm, Tx, n, Match, data, arg); /*目前都是用的这个*/
        }
        else if(acsm->acsmFormat == ACF_BANDED)
        {
            // return acsmSearchSparseDFA_Banded(acsm, Tx, n, Match,data);
        }
        else
        {
            //  return acsmSearchSparseDFA(acsm, Tx, n, Match,data);
        }

    case FSA_NFA:

        //  return acsmSearchSparseNFA(acsm, Tx, n, Match,data);

    case FSA_TRIE:

        return 0;
    }
    return 0;
}


void acsmSearchInit(acsm_search_info_t * acsm_search_info)
{
    acsm_search_info->state = 0;
    acsm_search_info->count = 0;
    acsm_search_info->seq   = AC_SEQUENCE_BGN;
    spin_lock_init(&acsm_search_info->lock);
}

int acsmSearch3(ACSM_STRUCT2 * acsm, unsigned char *Tx, int n,
        int(*Match)(void ** ids, int *indexs, int mcnt, void *data, int n, void*arg),
        void *data,void *arg)
{

    ACSM_PATTERN2   * mlist;
    unsigned char   * Tend;
    unsigned char   * T;
    int             indexs[5]; //一个串最多命中5个pattern
    void             *ids[5]; 
    int               index;
    acstate_t         state;
    acstate_t       * ps;
    acstate_t         sindex;
    acstate_t      ** NextState = acsm->acsmNextState;
    ACSM_PATTERN2  ** MatchList = acsm->acsmMatchList;
    int               nfound    = 0;

    T    = Tx;
    Tend = Tx + n;

    //printk("T = %x %x %x %x,acsmMaxStates = %d\n",T[0],T[1],T[2],T[3],acsm->acsmMaxStates);

    for(state = 0; T < Tend; T++)
    {
#ifdef ACSMMATCHLIST_LOCK
        spin_lock(&acsm->lock_acsmMatchList);
#endif

        ps     = NextState[ state ];

        sindex = xlatcase[ T[0] ];

        //  printk("state = %d,sindex = %d\n",state,sindex);
        if(ps[1])
        {
            for(mlist = MatchList[state];
                    mlist!= NULL;
                    mlist = mlist->next)
            {
                index = T - mlist->n - Tx;

                if(mlist->nocase)
                {
                   indexs[nfound] = index;
                    ids[nfound] = mlist->id;
                    if (++nfound >= 5) {
#ifdef ACSMMATCHLIST_LOCK
                        spin_unlock(&acsm->lock_acsmMatchList);
#endif
                        goto out;
                    }
                }
                else
                {
                    if(memcmp(mlist->casepatrn, Tx + index, mlist->n) == 0)
                    {
                        indexs[nfound] = index;
                        ids[nfound] = mlist->id;
                        if (++nfound >= 5) {
#ifdef ACSMMATCHLIST_LOCK
                            spin_unlock(&acsm->lock_acsmMatchList);
#endif                            
                            goto out;
                        }
                    }
                }
            }
        }

        state = ps[ 2u + sindex ];
#ifdef ACSMMATCHLIST_LOCK
        spin_unlock(&acsm->lock_acsmMatchList);
#endif        
    }
#ifdef ACSMMATCHLIST_LOCK
    spin_lock(&acsm->lock_acsmMatchList);
#endif
    for(mlist = MatchList[state];
            mlist!= NULL;
            mlist = mlist->next)
    {
        index = T - mlist->n - Tx;

        if(mlist->nocase)
        {
            indexs[nfound] = index;
            ids[nfound] = mlist->id;
            if (++nfound >= 5) {
#ifdef ACSMMATCHLIST_LOCK
                spin_unlock(&acsm->lock_acsmMatchList);
#endif                
                goto out;
            }
        }
        else
        {
            if(memcmp(mlist->casepatrn, Tx + index, mlist->n) == 0)
            {
                indexs[nfound] = index;
                ids[nfound] = mlist->id;
                if (++nfound >= 5) {
#ifdef ACSMMATCHLIST_LOCK
                    spin_unlock(&acsm->lock_acsmMatchList);
#endif                    
                    goto out;
                }
            }
        }
    }
#ifdef ACSMMATCHLIST_LOCK
    spin_unlock(&acsm->lock_acsmMatchList);
#endif    
out:
    if (nfound > 0) 
        Match(ids, indexs, nfound, data, n, arg);
    return nfound;
}

/*
*   Free all memory
*/
void acsmFree2(ACSM_STRUCT2 * acsm)
{
    int i;
    ACSM_PATTERN2 * mlist, *ilist;

    //ALERT("acsmFree2\n");

    mlist = acsm->acsmPatterns;
    while(mlist)
    {
        //ALERT("pattern %s\n", mlist->casepatrn);
        ilist = mlist;
        mlist = mlist->next;

        AC_FREE(ilist->patrn);
        AC_FREE(ilist->casepatrn);
        AC_FREE(ilist);
    }

    for(i = 0; i < acsm->acsmMaxStates; i++)
    {
        mlist = acsm->acsmMatchList[i];

        while(mlist)
        {
            ilist = mlist;
            mlist = mlist->next;

            AC_FREE(ilist);
        }
        //ALERT("acsmNextState[%d]\n", i);
        AC_FREE(acsm->acsmNextState[i]);
    }

    AC_FREE(acsm->acsmNextState);
    AC_FREE(acsm->acsmMatchList);
    AC_FREE(acsm->acsmFailState);
    AC_FREE(acsm);

}

/*
*
*/
void acsmPrintInfo2(ACSM_STRUCT2 * p)
{
    char * sf[]=
    {
        "Full Matrix",
        "Sparse Matrix",
        "Banded Matrix",
        "Sparse Banded Matrix",
    };
    char * fsa[]=
    {
        "TRIE",
        "NFA",
        "DFA",
    };


    ALERT("+--[Pattern Matcher:Aho-Corasick]-----------------------------\n");
    ALERT("| Alphabet Size    : %d Chars\n",p->acsmAlphabetSize);
    ALERT("| Sizeof State     : %d bytes\n",(int)(sizeof(acstate_t)));
    ALERT("| Storage Format   : %s \n",sf[ p->acsmFormat ]);
    ALERT("| Sparse Row Nodes : %d Max\n",p->acsmSparseMaxRowNodes);
    ALERT("| Sparse Band Zeros: %d Max\n",p->acsmSparseMaxZcnt);
    ALERT("| Num States       : %d\n",p->acsmNumStates);
    ALERT("| Num Transitions  : %d\n",p->acsmNumTrans);
    ALERT("| State Density    : %d%%\n",100*p->acsmNumTrans/(p->acsmNumStates*p->acsmAlphabetSize));
    ALERT("| Finite Automatum : %s\n", fsa[p->acsmFSA]);
    if(max_memory < 1024*1024)
    {
        ALERT("| Memory           : %zdKbytes\n", max_memory << 10);
    }
    else
    {
        ALERT("| Memory           : %zdMbytes\n", max_memory << 20);
    }
    ALERT("+-------------------------------------------------------------\n");

    /* Print_DFA(acsm); */

}

/*
 *
 */
int acsmPrintDetailInfo2(ACSM_STRUCT2 * p)
{

    return 0;
}

/*
 *   Global sumary of all info and all state machines built during this run
 *   This feeds off of the last pattern groupd built within snort,
 *   all groups use the same format, state size, etc..
 *   Combined with accrued stats, we get an average picture of things.
 */
int acsmPrintSummaryInfo2(void)
{
    char * sf[]=
    {
        "Full",
        "Sparse",
        "Banded",
        "Sparse-Bands",
    };

    char * fsa[]=
    {
        "TRIE",
        "NFA",
        "DFA",
    };

    ACSM_STRUCT2 * p = &summary.acsm;

    if(!summary.num_states)
        return 0;

    ALERT("+--[Pattern Matcher:Aho-Corasick Summary]----------------------\n");
    ALERT("| Alphabet Size    : %d Chars\n",p->acsmAlphabetSize);
    ALERT("| Sizeof State     : %d bytes\n",(int)(sizeof(acstate_t)));
    ALERT("| Storage Format   : %s \n",sf[ p->acsmFormat ]);
    ALERT("| Num States       : %d\n",summary.num_states);
    ALERT("| Num Transitions  : %d\n",summary.num_transitions);
    ALERT("| State Density    : %d%%\n",100*summary.num_transitions/(summary.num_states*p->acsmAlphabetSize));
    ALERT("| Finite Automatum : %s\n", fsa[p->acsmFSA]);
    if(max_memory < 1024*1024)
    {
        ALERT("| Memory           : %zdKbytes\n", max_memory/1024);
    }
    else
    {
        ALERT("| Memory           : %zdMbytes\n", max_memory/(1024*1024));
    }
    ALERT("+-------------------------------------------------------------\n");


    return 0;
}
#define ACSM_SEGMENT_FLAGS_MASK   (3UL)
#define ACSM_SEGMENT_POINTER_MASK (~IPV4_SEGMENT_FLAGS_MASK)


/* --------- /proc interface part --------- */

struct acsm_rules_proc
{
#define ACSM_PROC_WBUF_SZ  2048
	char    wbuf[ACSM_PROC_WBUF_SZ + 20];
	size_t  wbuf_sz;
	size_t  wpos;
	/* Length of the output string */
	char   *rbuf;
	size_t  rbuf_len;
	size_t  rpos;
};
/**
 * Structure for printing rule table.
 */
struct buffer_s
{
#define BUFFER_LINE_SZ 128
	char   line[BUFFER_LINE_SZ];
	size_t len;
	struct buffer_s *next;
};

static inline void acsm_rules_clean_rcu(struct acsm_rules *rules)
{
    ACSM_STRUCT2 *acsm = rules->acsm;

    rcu_assign_pointer(rules->acsm, NULL);

    synchronize_rcu();
    acsmFree2(acsm);
}
/* Add one L1 block for the whole IPv4 address space */
static int acsm_rules_add_rcu(struct acsm_rules *rules, const char *key, const int key_len, unsigned long data)
{
	ACSM_STRUCT2 *acsm = NULL;
	rcu_read_lock();
	acsm = rcu_dereference(rules->acsm);
    acsmAddPattern2(acsm, key, key_len, 1, 0, 0, (char *)rules->pattern + (rules->id * rules->pattern_size), rules->id);
    ++rules->id;
	rcu_read_unlock();
	return 0;
}

bool acsm_rules_check(struct acsm_rules *rules, const char *key, unsigned long *edata)
{
    ACSM_STRUCT2 *acsm;
	bool retv = false;
	unsigned long __edata = 0;
    ACSM_PATTERN2 * plist;
    int len;
	
	rcu_read_lock();

	acsm = rcu_dereference(rules->acsm);
    len = strlen(key);
    for (plist = acsm->acsmPatterns; plist; plist = plist->next) {
        if (plist->n == len &&strncmp(plist->casepatrn, key, len) == 0) {
            retv = true;
            __edata = (unsigned long)plist;
            goto to_exit;
        }

    }
    
	/* It won't actually get here */
	rcu_read_unlock();
    LOG_INFO("test %s failt\n", key);
	return false;

to_exit:
	rcu_read_unlock();
    LOG_INFO("test %s ok\n", key);
	if(edata)
		*edata = __edata;
	return retv;
}

static int  build_rules(struct acsm_rules *rules)
{
    int retv = 0;
    down_write(&rules->rwsem);
    if(acsmCompile2(rules->acsm) == -1) {
        acsm_rules_clean_rcu(rules);
        if (rules->fn_init_acsm) {
            rules->fn_init_acsm(rules);
            rules->have_build = 0;
        }
        retv = -1;
    }
    up_write(&rules->rwsem);
    return retv;
}

static int acsm_rules_cmd_parse(struct acsm_rules *rules, char *cmd, struct acsm_rules_proc *proc)
{
	char *a1 = NULL, *a2 = NULL;
	char *sep;
	char sc;
	int n = 32;
    char *sp,*ln_start, *key_str = NULL, *action_str = NULL, *action_end_str = NULL, *extra_key_str = NULL;
    uint32_t action = 0;  
	// -------------------------------
	unsigned long data = 0;
    char *key = NULL; int key_len = 0;
	// -------------------------------
    //printk("cmd:%s\n",cmd);
    //LOG_INFO("cmd:%s\n",cmd);
	if(strcmp(cmd, "c") == 0 || strncmp(cmd, "clear", 5) == 0)
	{
		/* Case 1: 'clear' command. */
		/* ------------------------------------ */
		down_write(&rules->rwsem);
		acsm_rules_clean_rcu(rules);
		if(rules->fn_clear)
			rules->fn_clear(rules);
        if (rules->fn_init_acsm) {
            rules->fn_init_acsm(rules);
        }

        rules->have_build = 0;
	    proc->rbuf_len = proc->rpos = 0;
		proc->wbuf_sz =  proc->wpos = 0;
		up_write(&rules->rwsem);
		/* ------------------------------------ */
		return 0;
	} else if (strcmp(cmd, "b") == 0 || strncmp(cmd, "build", 5) == 0) {
        if (build_rules(rules) == 0) {
            rules->have_build = 1;
        }
        LOG_INFO("have_build=%d\n",rules->have_build);
        return 0;
    }
	else if(strncmp(cmd, "t ", 2) == 0)
	{
		/* Case 2: 't' command (test method). */
		a1 = cmd + 2;
		if(acsm_rules_check(rules, a1, NULL))
			return 0;
		else
			return -EINVAL;
	}
    if (rules->have_build == 1) {
        LOG_INFO("haven build acsm\n");
        return 0;
    }
    if (rules->fn_pattern_parse == NULL) {
        return 0;
    }
    key_str = NULL;
    action_str = NULL;
    action_end_str = NULL;
    extra_key_str = NULL;

    action = 0;  
    for(ln_start = cmd; (sp = strchr(ln_start, '\n')); ln_start = sp + 1)
    {   
        *sp = '\0';
        trim(ln_start);
        key = NULL; key_len = 0;
        if (rules->fn_pattern_parse(rules, ln_start, &key, &key_len) == 0) {

        }
        if (key_len > 0) {
            down_write(&rules->rwsem);
            acsm_rules_add_rcu(rules, key, key_len, data);
            up_write(&rules->rwsem);
        }
    }
    if (ln_start != NULL) {
        trim(ln_start);
        key = NULL; key_len = 0;
        if (rules->fn_pattern_parse(rules, ln_start, &key, &key_len) == 0) {

        }
        if (key_len > 0) {
            down_write(&rules->rwsem);
            acsm_rules_add_rcu(rules, key, key_len, data);
            up_write(&rules->rwsem);
        }
    }

	return 0;
}

static ssize_t acsm_rules_proc_write(struct file *file, const char __user *data, size_t count, loff_t *f_pos)
{
    struct inode *inode;
    struct acsm_rules *rules;
    struct acsm_rules_proc *proc;
    size_t len, __count;
    char *ln_start, *ln_end;
    int ret;
    if (strncmp(CURRENT_COMM, "MagicArmor_0", 12) !=0) {
		return -EINVAL;
    }
	inode = file->f_path.dentry->d_inode;
	rules = (struct acsm_rules *)OSEC_PDE_DATA(inode);

	proc = (struct acsm_rules_proc *)file->private_data;
	__count = count;
	while(count > 0)
	{
		len = proc->wbuf_sz - proc->wpos;
		if(count < len)
			len = count;
		if(len == 0)
			return -EINVAL;
		
		if(copy_from_user(proc->wbuf + proc->wpos, data, len))
			return -EFAULT;
		proc->wpos += len;
		
		/* Pick out each possible line */
		for(ln_start = proc->wbuf;
			ln_start < proc->wbuf + proc->wpos &&
			( ln_end = (char *)memchr(ln_start, '\n', (size_t)(proc->wbuf + proc->wpos - ln_start)) );
			ln_start = ln_end + 1)
		{
			*ln_end = '\0';
			/* Parse and do operations on current line*/
			if(ln_end - ln_start > 0)
			{
				if((ret = acsm_rules_cmd_parse(rules, ln_start, proc)) < 0)
				{
					proc->wpos = 0;
					return ret;
				}
			}
		}
		/* Move the incomplete line data ahead */
		if(ln_start > proc->wbuf)
		{
			if(ln_start < proc->wbuf + proc->wpos)
			{
				size_t remained = (size_t)(proc->wbuf + proc->wpos - ln_start);
				memmove(proc->wbuf, ln_start, remained);
				proc->wpos = remained;
			}
			else
				proc->wpos = 0;
		}
		
		data += len;
		count -= len;
	}

	return __count - count;
}
#if 0
static inline size_t acsm_show(
		struct acsm_rules *rules,
		struct buffer_s ***curpp, 
		unsigned long edata )
{
	struct buffer_s **curp = *curpp;
	char s1[20], s2[20];
	//char line[50];
	size_t len;
	char *dp;

	if((*curp = (struct buffer_s *)kzalloc(sizeof(struct buffer_s), GFP_KERNEL)) == NULL)
		return 0;
	(*curp)->next = NULL;

	dp = (*curp)->line;

    ACSM_STRUCT2 *acsm;
	
	rcu_read_lock();

	acsm = rcu_dereference(rules->acsm);
    ACSM_PATTERN2 * plist;
    for (plist = acsm->acsmPatterns; plist; plist = plist->next) {
		sprintf(dp, "%s,len=%d\n", plist->casepatrn, plist->n);
        LOG_INFO("===========[%s]\n",dp);
        //strncat(dp,"\n",1);
	    dp += strlen(dp);
    }
	/* It won't actually get here */
	rcu_read_unlock();


	if(rules->fn_show_edata)
	{
		*(dp++) = ' ';
		rules->fn_show_edata(edata, dp);
		dp += strlen(dp);
	}

	//sprintf(dp, "\n");

	len = (*curp)->len = strlen((*curp)->line);
	*curpp = &(*curp)->next;

	return len;
}
#else
static inline size_t acsm_show(
        ACSM_PATTERN2 * plist,
		struct buffer_s ***curpp, 
		unsigned long edata )
{
	struct buffer_s **curp = *curpp;
	char s1[20], s2[20];
	//char line[50];
	size_t len;
	char *dp;

	if((*curp = (struct buffer_s *)kzalloc(sizeof(struct buffer_s), GFP_KERNEL)) == NULL)
		return 0;
	(*curp)->next = NULL;
	dp = (*curp)->line;
    //sprintf(dp, "%s,len=%d\n", plist->casepatrn, plist->n);
    sprintf(dp, "%.*s,len=%d\n", plist->n, plist->casepatrn, plist->n);

    //strncat(dp,"\n",1);
    dp += strlen(dp);
    /* It won't actually get here */

	//sprintf(dp, "\n");

	len = (*curp)->len = strlen((*curp)->line);
	*curpp = &(*curp)->next;

	return len;
}
#endif
static char *acsm_rules_show_mem(struct acsm_rules *rules, size_t *lenp)
{
	__rtype_t    l3_val;
	int i, j, k;
	__u32 start = 0, end = 0;
	unsigned long __edata = 0;
	struct buffer_s *head = NULL, **curp = &head, *cur, *cur_next;
	char *data;
	size_t len = 0, wpos;
    //len += acsm_show(rules, &curp,  __edata);

    ACSM_PATTERN2 * plist;
    ACSM_STRUCT2 *acsm;
	rcu_read_lock();
	acsm = rcu_dereference(rules->acsm);
    for (plist = acsm->acsmPatterns; plist; plist = plist->next) {
        len += acsm_show(plist, &curp,  __edata);
    }
	rcu_read_unlock();

	if(len == 0)
	{
		*lenp = len;
		return NULL;
	}
	if((data = (char *)kmalloc(len, GFP_KERNEL| __GFP_ZERO)) == NULL)
	{
		for(cur = head; cur; cur = cur_next)
		{
			cur_next = cur->next;
			kfree(cur);
		}
		*lenp = len;
		return NULL;
	}
	for(cur = head, wpos = 0; cur; cur = cur_next)
	{
		cur_next = cur->next;
		if(!(wpos < len))
			break;
		memcpy(data + wpos, cur->line, cur->len);
		wpos += cur->len;
		kfree(cur);
	}
	*lenp = len;
	return data;
}

static ssize_t acsm_rules_proc_read(struct file *file, char __user *data, size_t count, loff_t *f_pos)
{
	struct inode *inode = file->f_path.dentry->d_inode;
	struct acsm_rules *rules = (struct acsm_rules *)OSEC_PDE_DATA(inode);
	struct acsm_rules_proc *proc = (struct acsm_rules_proc *)file->private_data;
	size_t len;
	
    if (is_enable_show_proc() == 0) {
		return -EINVAL;
    }
	if(proc->rbuf == NULL)
	{
		/* ------------------------------------ */
		down_read(&rules->rwsem);
		proc->rbuf = acsm_rules_show_mem(rules, &proc->rbuf_len);
		up_read(&rules->rwsem);
		/* ------------------------------------ */
		proc->rpos = 0;
	}
	if((len = proc->rbuf_len - proc->rpos) == 0) {
		return 0;
    }
	if(count < len)
		len = count;
	
	if(copy_to_user(data, proc->rbuf + proc->rpos, len))
		return -EFAULT;
	proc->rpos += len;

	return len;
}

static int acsm_rules_proc_open(struct inode *inode, struct file *file)
{
	//struct acsm_rules *rules = (struct acsm_rules *)PDE(inode)->data;
	struct acsm_rules_proc *proc;
    	
	if((proc = (struct acsm_rules_proc *)kmalloc(sizeof(struct acsm_rules_proc), GFP_KERNEL)) == NULL)
		return -ENOMEM;
	memset(proc, 0x0, sizeof(struct acsm_rules_proc));
	file->private_data = proc;
	proc->wbuf_sz = ACSM_PROC_WBUF_SZ;
	proc->wpos = 0;
    LOG_INFO("success open acsm rules\n");
	return 0;
}

static int acsm_rules_proc_release(struct inode *inode, struct file *file)
{
	struct acsm_rules *rules = (struct acsm_rules *)OSEC_PDE_DATA(inode);
	struct acsm_rules_proc *proc = (struct acsm_rules_proc *)file->private_data;

	/* Parse the last unfinished line on close */
	if(proc->wpos > 0 && proc->wpos < proc->wbuf_sz)
	{
		proc->wbuf[proc->wpos] = '\0';
        if (rules)
		    acsm_rules_cmd_parse(rules, proc->wbuf, proc);
	}
	/* Release the read buffer on close */
	if(proc->rbuf)
		kfree(proc->rbuf);
	kfree(proc);
	file->private_data = NULL;
	return 0;
}

//#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
static const struct proc_ops acsm_rules_proc_fops =
{
	//.owner   = THIS_MODULE,
	.proc_read   = acsm_rules_proc_read,
	.proc_write   = acsm_rules_proc_write,
	.proc_open    = acsm_rules_proc_open,
	.proc_release = acsm_rules_proc_release,
    .proc_lseek   = default_llseek,
};
#else
static const struct file_operations acsm_rules_proc_fops =
{
	.owner   = THIS_MODULE,
	.read   = acsm_rules_proc_read,
	.write   = acsm_rules_proc_write,
	.open    = acsm_rules_proc_open,
	.release = acsm_rules_proc_release,
    .llseek   = default_llseek,
};
#endif

int acsm_rules_init(struct acsm_rules *rules, const char *proc_name, struct proc_dir_entry *proc_parent)
{
	//rules->acsm = NULL;
	init_rwsem(&rules->rwsem);
	if(proc_name)
	{
		rules->proc_name = proc_name;
		rules->proc_parent = proc_parent;
		proc_create_data(proc_name, 0644, proc_parent, &acsm_rules_proc_fops, rules);
	}
	else
	{
		rules->proc_name = NULL;
		rules->proc_parent = NULL;
	}
	return 0;
}

void acsm_rules_purge(struct acsm_rules *rules)
{
	if(rules->proc_name)
		remove_proc_entry(rules->proc_name, rules->proc_parent);
	down_write(&rules->rwsem);
	acsm_rules_clean_rcu(rules);
	up_write(&rules->rwsem);
}
EXPORT_SYMBOL(acsm_rules_init);
EXPORT_SYMBOL(acsm_rules_purge);


