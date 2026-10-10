#ifndef __CON_KERNEL_UTILS_H__
#define __CON_KERNEL_UTILS_H__

#include <linux/types.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/ctype.h>
#include <linux/version.h>
#include <linux/highmem.h>
#include <linux/if_ether.h>
#include "core/kvd_core.h" //for bool

//just for case
#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,23)
    //get the pid-id seen from the init namespace
    #define PID(ts) task_tgid_nr(ts)
#else
    #define PID(ts) ((ts)->tgid)
#endif


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,18,0)
#define OSEC_PDE_DATA(inode) pde_data(inode)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5,15,0) || SPEC_VERSION_BUILD == 2
#define OSEC_PDE_DATA(inode) PDE_DATA(inode)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5,14,0)
#define OSEC_PDE_DATA(inode) pde_data(inode)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
#define OSEC_PDE_DATA(inode) PDE_DATA(inode)
#else
#define OSEC_PDE_DATA(inode) PDE(inode)->data
#endif

/* uid and euid */
#define EUID(ts) kvd_get_task_euid((ts))
#define UID(ts)  kvd_get_task_uid((ts))
#define EGID(ts) kvd_get_task_egid((ts))
#define GID(ts)  kvd_get_task_gid((ts))
#define COMM(ts) (ts->group_leader)->comm

#define CURRENT_PID PID(current)
#define CURRENT_EUID EUID(current)
#define CURRENT_UID UID(current)
#define CURRENT_COMM (current->group_leader)->comm

#define CURRENT_PPID   PID(current->parent)
#define CURRENT_COMM_P ((current->parent)->group_leader)->comm


#define IPQUADS(addr) \
        ((unsigned char *)&addr)[0], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]
#define IPQUAD_FMT "%u.%u.%u.%u"
#define IPQUADL(addr) \
        ((unsigned char *)&addr)[3], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[0]




static inline void trim(char *str) {
    int i, j;
    int len = strlen(str);

    // 移除开始处的空格
    for (i = 0; i < len && str[i] == ' '; i++)
        ;

    // 复制非空格字符到开始位置
    for (j = i; j < len; j++)
        str[j - i] = str[j];

    // 移除结尾处的空格
    while (j > 0 && str[j - 1] == ' ')
        j--;

    // 添加结束标记
    str[j] = '\0';
}


char* vsec_get_task_comm(char* buf,size_t buf_size,
                    struct task_struct* task);
int vsec_get_exec_comm(char comm[TASK_COMM_LEN],
                const char* exe,unsigned exelen);
int match_task_family(struct task_struct* ts, int root_pid);
//一定要在持有rcu_read_lock的情况下调用该函数
int match_task_family_locked(struct task_struct* ts, int root_pid);

//查找pid是否属于当前的root_pid标识的进程家族
int match_pid_family(int pid, int root_pid);

//Note: we must hold the lock,before call the function
struct task_struct* get_parent(struct task_struct* tsk);
/////////////////////////////
int string_include(const char* s, const char* tmpl);
int string_ment_include(const char* s, const char* tmpl);
bool get_http_host(unsigned char *tcp_data,size_t tcp_data_len,
                char **host, int *psize);
size_t hex_str_mac(u_char mac[ETH_ALEN],
                    char* hex_buf);
bool is_http_method(const char* method,size_t len);
bool try_get_http_host(u_char* tcp_data,size_t tcp_data_len,
                    char** phost,int* host_len,int* bhttp);
pid_t vsec_get_ppid(struct task_struct* tsk);
int vsec_is_kthread(struct task_struct* task);

int parse_char_sep_data(void* data,size_t data_len,u_char sep,
    int (*cb)(void* item,size_t len,void* ctx),void* ctx);
//获取系统启动以来的纳秒
uint64_t vsec_get_now_nsec(void);
//获取系统启动以来的秒数
uint64_t vsec_get_now_sec(void);
//获取的1970年到现在秒数
uint64_t vsec_get_seconds(void);
bool vsec_is_devloop(const char* name);

bool vsec_path_equal(const struct path* path1,
                    const struct path* path2);

void* vsec_kmap_atomic(struct page *page);
void vsec_kunmap_atomic(void* kaddr);

void vsec_disable_preempt(void);
void vsec_enable_preempt(void);
//此函数用来获取某路径的真实路径
char* get_realpath(const char* pathname,
                unsigned* plen,struct kstat* pst);
//做一些基本的初始化操作，
//预期是不会失败的
void vsec_utils_init(void);
void vsec_utils_uninit(void);

#define KOSEC_PATH_LEN 256
//读取文件内容
//成功返回0,pres为vmalloc分配的buf(外围使用完需释放),失败返回-EXXX
//buf的前plen长度是实际配置文件路径(无\0分割),后dlen是配置文件内容(以\0结尾)
//|path|content|
int vsec_file_read(const char *file, size_t flen,
        char **pres, size_t *plen, size_t *dlen);
static inline char osec_tolower(char c) {
    if (c >= 'A' && c <= 'Z') {
        return c + ('a' - 'A');
    }
    return c;
}

static inline unsigned __isspace(char c)
{
	return (c == ' ' || c == '\t' || c == '\r' || c == '\n');
}

static inline unsigned __isblank(char c)
{
	return (c == ' ' || c == '\t');
}


static inline char *port_nstos(__u16 u, char *s)
{
	static char hs[10];
	if(!s) s = hs;
	sprintf(s, "%d",
		(uint16_t)(u << 8 | u >> 8));
	return s;
}
static inline char *port_hstos(__u16 u, char *s)
{
	static char hs[10];
	if(!s) s = hs;
	sprintf(s, "%d", u);
	return s;
}

static inline char *ipv4_hltos(__u32 u, char *s)
{
	static char hs[20];
	if(!s) s = hs;
	sprintf(s, "%d.%d.%d.%d",
		(int)(u >> 24) & 0xff,
		(int)(u >> 16) & 0xff,
		(int)(u >> 8) & 0xff,
		(int)u & 0xff );
	return s;
}
static inline char *ipv4_nltos(__u32 u, char *s)
{
	static char hs[20];
	if(!s) s = hs;
	sprintf(s, "%d.%d.%d.%d",
		(int)u & 0xff,
		(int)(u >> 8) & 0xff,
		(int)(u >> 16) & 0xff,
		(int)(u  >> 24) & 0xff );
	return s;
}
static inline __u32 ipv4_stohl(const char *s)
{
	int u[4];
	if(sscanf(s, "%d.%d.%d.%d", &u[0], &u[1], &u[2], &u[3]) == 4)
	{
		return  (((__u32)u[0] & 0xff) << 24) |
				(((__u32)u[1] & 0xff) << 16) |
				(((__u32)u[2] & 0xff) << 8) |
				(((__u32)u[3] & 0xff));
	}
	else
		return 0xffffffff;
}
static inline __u32 ipv4_stonl(const char *s)
{
	int u[4];
	if(sscanf(s, "%d.%d.%d.%d", &u[0], &u[1], &u[2], &u[3]) == 4)
	{
		return  (((__u32)u[0] & 0xff)) |
				(((__u32)u[1] & 0xff) << 8) |
				(((__u32)u[2] & 0xff) << 16) |
				(((__u32)u[3] & 0xff) << 24);
	}
	else
		return 0xffffffff;
}
static inline __u16 port_stons(const char *s)
{
    uint32_t u;
	if(sscanf(s, "%u", &u) == 1)
	{
		return (uint16_t)htons(u);
	}
	else
		return 0xffff;
}
static inline __u16 port_stohs(const char *s)
{
	int u[2];
	if(sscanf(s, "%d%d", &u[0], &u[1]) == 2)
	{
		return  (((__u16)u[1] & 0xff)) |
				(((__u16)u[0] & 0xff) << 8);
	}
	else
		return 0xffff;
}

static inline int is_u8(const char *s)
{
	__u8 u;
	if(sscanf(s, "%c", &u) == 1)
		return true;
	else
		return false;
}

static inline int is_u32(const char *s)
{
	__u32 u;
	if(sscanf(s, "%u", &u) == 1)
		return true;
	else
		return false;
}

static inline int is___u16(const char *s)
{
	__u16 u;
	if(sscanf(s, "%hu", &u) == 1)
		return true;
	else
		return false;
}

static inline int is_ipv4_addr(const char *s)
{
	int u[4];
	if(sscanf(s, "%d.%d.%d.%d", &u[0], &u[1], &u[2], &u[3]) == 4)
		return true;
	else
		return false;
}
#if 1 
static inline void init_list_entry(struct list_head *entry)
{
	entry->next = LIST_POISON1;
	entry->prev = LIST_POISON2;
}

static inline int list_entry_orphan(struct list_head *entry)
{
	return entry->next == LIST_POISON1;
}
#endif
static inline int is_trim(char c,const char *sp)
{
    int i;
    int sp_len = strlen(sp);
    if (isspace(c)||c == '\n'|| c == '\r')
        return 1;
    for (i = 0; i < sp_len; i ++) {
        if (c == sp[i])
            return 1;
    }
    return 0;
}

static inline char *trim_specific(char *s, const char *sp)
{
    int i = 0,cp_point = 0;
    char * c = s + strlen(s) - 1;
    char * cpst;

    while (is_trim(*c, sp) && c >= s)
    {
        *c = '\0';
        --c;
    }

    c = s;
    while(*c != '\0')
    {
        if(is_trim(*c, sp))
        {
            i++;
        }
        else
        {
            break;
        }
        c++;
    }

    if(i != 0 )
    {
        cpst = s + i;
        while(*cpst != '\0')
        {
            *(s + cp_point) = *cpst;
            cp_point++;
            cpst++;
        }
        *(s + cp_point) = '\0';
    }
    return s;
}

static inline int ch_isspace(char c)
{
    return c == ' ' || c == '\r' || c == '\n' || c == '\t';
}
static inline void trim_spaces(char *str)
{
    char *p1, *p2, c;
    size_t len;

    if((len = strlen(str)) == 0)
        return;

    /* Determine start position. */
    for(p1 = str; (c = *p1); p1++)
    {
        if(!ch_isspace(c))
            break;
    }

    /* Determine ending position. */
    for(p2 = str + len; p2 > p1 && (c = *(p2 - 1)); p2--)
    {
        if(!ch_isspace(c))
            break;
    }

    /* Move string ahead, and put new terminal character. */
    memmove(str, p1, (size_t)(p2 - p1));
    str[(size_t)(p2 - p1)] = '\0';
}
static inline int __ch_isspace(char c)
{
    return c == ' ' || c == '\r' || c == '\n' || c == '\t'||c == '['||
            c == ']'|| c == '{' || c == '}';
}
static inline void _strim(char *str)
{
    char *p1, *p2, c;
    size_t len;

    if((len = strlen(str)) == 0)
        return;

    /* Determine start position. */
    for(p1 = str; (c = *p1); p1++)
    {
        if(!__ch_isspace(c))
            break;
    }

    /* Determine ending position. */
    for(p2 = str + len; p2 > p1 && (c = *(p2 - 1)); p2--)
    {
        if(!__ch_isspace(c))
            break;
    }

    /* Move string ahead, and put new terminal character. */
    memmove(str, p1, (size_t)(p2 - p1));
    str[(size_t)(p2 - p1)] = '\0';
}
static inline int __ch_spec(char c)
{
    return c == '\r' || c == '\n' || c == '\t'||c == '['||
            c == ']'|| c == '{' || c == '}';
}

static inline void strim_except_space(char *str)
{
    char *p1, *p2, c;
    size_t len;

    if((len = strlen(str)) == 0)
        return;

    /* Determine start position. */
    for(p1 = str; (c = *p1); p1++)
    {
        if(!__ch_spec(c))
            break;
    }

    /* Determine ending position. */
    for(p2 = str + len; p2 > p1 && (c = *(p2 - 1)); p2--)
    {
        if(!__ch_spec(c))
            break;
    }

    /* Move string ahead, and put new terminal character. */
    memmove(str, p1, (size_t)(p2 - p1));
    str[(size_t)(p2 - p1)] = '\0';
}

static inline int __ch_spec2(char c)
{
    return c == '\r' || c == '\n' || c == '\t';
}

static inline void strim_except_space2(char *str)
{
    char *p1, *p2, c;
    size_t len;

    if((len = strlen(str)) == 0)
        return;

    /* Determine start position. */
    for(p1 = str; (c = *p1); p1++)
    {
        if(!__ch_spec2(c))
            break;
    }

    /* Determine ending position. */
    for(p2 = str + len; p2 > p1 && (c = *(p2 - 1)); p2--)
    {
        if(!__ch_spec2(c))
            break;
    }

    /* Move string ahead, and put new terminal character. */
    memmove(str, p1, (size_t)(p2 - p1));
    str[(size_t)(p2 - p1)] = '\0';
}

static inline int nocase_cmp(int key1, int key2)
{
        if (((key1 >= 97 && key1 <= 122) || (key1 >= 65 && key1 <= 90)) \
        &&((key2 >= 97 && key2 <= 122) || (key2 >= 65 && key2 <= 90))) {
                switch (key1 - key2){
                        case 0:
                        case 32:
                        case -32:
                                return 0;
                        default:
                                return 1;

                }

        }
        return (key1 != key2);


}

static inline void nocase_next_index(const char *str, int len, int next[])
{

        int i = 0, j = -1;

        next[i] = -1;

        while ( i < len) {
                if ( j == -1 || !(nocase_cmp(str[i] ,str[j]))) {
                        j ++;
                        i ++;
                        if (nocase_cmp(str[i], str[j])) {
                                next[i] = j;
                        } else {
                                next[i] = next[j];
                        }
                } else {

                        j = next[j];
                }

        }
}
static inline int substr_in_mainstr_nocase(const char *mstr,int mlen, const char *pstr, char meta)
{
    int i = 0, j = 0;
    int plen = strlen(pstr);

    int next[plen];
    nocase_next_index(pstr, plen, next);
    if (meta == 0) {
        while (i < mlen && j < plen) {
                if (!nocase_cmp(mstr[i], pstr[j])) {
                        i ++;
                        j ++;
                } else {
                        if (next[j] != -1)
                                j = next[j];
                        else {
                                j = 0;
                                i ++;
                        }
                }

        }

    } else {
        while (i < mlen && j < plen) {
                if (!nocase_cmp(mstr[i], meta))
                    break;
                if (!nocase_cmp(mstr[i], pstr[j])) {
                        i ++;
                        j ++;
                } else {
                        if (next[j] != -1)
                                j = next[j];
                        else {
                                j = 0;
                                i ++;
                        }
                }

        }


    }
    if (j >= plen)
        //return i - plen;
        return i;
    return -1;
}

static inline int cmp(uint8_t key1, uint8_t key2)
{
    return (key1 != key2);
}

static inline void next_index(const char *str, int len, int next[])
{

        int i = 0, j = -1;

        next[i] = -1;

        while ( i < len) {
                if ( j == -1 || !(cmp(str[i] ,str[j]))) {
                        j ++;
                        i ++;
                        if (cmp(str[i], str[j])) {
                                next[i] = j;
                        } else {
                                next[i] = next[j];
                        }
                } else {

                        j = next[j];
                }

        }
}
static inline int substr_in_mainstr(const char *mstr, int mlen, const char *pstr, char meta)
{
    int i = 0, j = 0;
    int plen = strlen(pstr);

    int next[plen];
    next_index(pstr, plen, next);
    if (meta == 0) {
        while (i < mlen && j < plen) {
                if (!cmp(mstr[i], pstr[j])) {
                        i ++;
                        j ++;
                } else {
                        if (next[j] != -1)
                                j = next[j];
                        else {
                                j = 0;
                                i ++;
                        }
                }

        }

    } else {
        while (i < mlen && j < plen) {
                if (mstr[i] == meta)
                    break;
                if (!cmp(mstr[i], pstr[j])) {
                        i ++;
                        j ++;
                } else {
                        if (next[j] != -1)
                                j = next[j];
                        else {
                                j = 0;
                                i ++;
                        }
                }

        }


    }
        if (j >= plen)
                return i;
        return -1;
}
static inline int subhex_in_mainhex(const char *mstr, int mlen, const char *pstr, const int plen, char meta)
{
    int i = 0, j = 0;

    int next[plen];
    next_index(pstr, plen, next);
    if (meta == 0) {
        while (i < mlen && j < plen) {
                if (!cmp(mstr[i], pstr[j])) {
                        i ++;
                        j ++;
                } else {
                        if (next[j] != -1)
                                j = next[j];
                        else {
                                j = 0;
                                i ++;
                        }
                }

        }

    } else {
        while (i < mlen && j < plen) {
//                if (mstr[i] == meta)
//                    break;
                if (!cmp(mstr[i], pstr[j])) {
                        i ++;
                        j ++;
                } else {
                        if (next[j] != -1)
                                j = next[j];
                        else {
                                j = 0;
                                i ++;
                        }
                }

        }


    }
        if (j >= plen)
                return i;
        return -1;
}


static inline char *str_trim(char *s)
{
        int i = 0,cp_point = 0;
        char * c = s + strlen(s) - 1;
        char * cpst;

        while ((isspace(*c) ||*c == '\n'|| *c == '\r'|| *c == '\t' ) && c >= s)
        {
                *c = '\0';
                --c;
        }

        c = s;
        while(*c != '\0')
        {
                if(isspace(*c)||*c == '\n'|| *c == '\r'||*c == '\t')
                {
                        i++;
                }
                else
                {
                        break;
                }
                c++;
        }

        if(i != 0 )
        {
                cpst = s + i;
                while(*cpst != '\0')
                {
                        *(s + cp_point) = *cpst;
                        cp_point++;
                        cpst++;
                }
                *(s + cp_point) = '\0';
        }
    return s;
}
static inline int strcmp_nocase(char * src, const char * mark)
{
    int i;
    int ret = 0;
    char s;
    char m;

    if (src == NULL || mark == NULL)
    {
        return -1;
    }

    for (i = 0;;i++)
    {
        s = tolower(*(src + i));
        m = tolower(*(mark + i));
        if (s > m)
        {
            ret = i + 1;
            break;
        }
        else if (s < m)
        {
            ret = 0 - i - 1;
            break;
        }

        if (s == 0 || m == 0)
        {
            break;
        }
    }
    return ret;
}
static inline int strncmp_nocase(char * src, const char * mark, int len)
{
    int i;
    int ret = 0;
    char s;
    char m;

    if (src == NULL || mark == NULL)
    {
        return -1;
    }

    for (i = 0; i < len; i++)
    {
        s = tolower(*(src + i));
        m = tolower(*(mark + i));
        if (s > m)
        {
            ret = i + 1;
            break;
        }
        else if (s < m)
        {
            ret = 0 - i - 1;
            break;
        }

        if (s == 0 || m == 0)
        {
            break;
        }
    }
    return ret;
}


//int md5_calculate_file(const char *filename, char *digest); 


#endif
