#include <linux/types.h>
#include "utils/utils.h"
#include "core/kvd_core.h"
#include "utils/hash_table.h"
#include "defense_inner.h"
#include "gnHead.h"

//默认不拦截的程序完整路径
static vsec_htable_t white_exes;

static uint32_t htable_hash_fn(void* data,size_t len)
{
    uint32_t hval = 0;
    hval = kvd_murmur_hash2(data,len);
    return hval;
}

static int htable_cmp_fn(void* key1,size_t len1,void* key2,size_t len2)
{
    int rc = 0;

    rc = (len1 - len2);
    if(rc) { return rc; }

    return memcmp(key1,key2,len1);
}

static void htable_free_fn(vsec_htable_t* ht,void* key,
							size_t key_len,void* data)
{
    LOG_DEBUG("free defense white exe path: %s\n",(char*)data);
    kfree(data);
}

static int add_white_exe(const char* exe,size_t size)
{
    int rc = -EINVAL;
    char* key = NULL; 
    char* data = NULL;
    size_t key_len = 0;

    if(!exe || !size || !*exe) {
        DEFENSE_LOG_ERROR("bad add defense white exe item\n");
        return rc;
    }

    rc = -ENOMEM;
    data = kstrndup(exe,size,GFP_KERNEL);
    if(!data) { return rc; }

    DEFENSE_LOG_DEBUG("add defense white exe: %s\n",data);
    key = data;
    key_len = strlen(data);

    rc = vsec_htable_upgrade(&white_exes,
                    key,key_len,data);
    if(rc) { kfree(data); }

    return rc;
}

static int del_white_exe(const char* exe,size_t size)
{
    int rc = -EINVAL;
    if(!exe || !size || !*exe) {
        DEFENSE_LOG_ERROR("bad del defense white exe item\n");
        return rc;
    }

    size = strlen(exe);
    return vsec_htable_del(&white_exes,(void*)exe,size);
}

void cleanup_white_exes(void)
{
    vsec_htable_cleanup(&white_exes);
}

static const char* uos_white_exes[] = {
        "/usr/bin/deepin-deb-installer-dependsInstall",
        "/usr/bin/deepin-deb-installer",
        "/usr/bin/qaptworker3",
        "/usr/bin/dpkg",
        "/usr/bin/lastore-daemon",
        "/usr/bin/apt-get",
        "/usr/bin/deepin-app-store"
    };

static void add_uos_white_exes(void)
{
//我们默认加白uos安装器相关的程序，不然无法通过商店升级我们
// #if defined(CONFIG_SECURITY_ELFVERIFY)
    size_t i = 0;
    for(;i < ARRAY_SIZE(uos_white_exes);i++) {
        add_white_exe(uos_white_exes[i],
            strlen(uos_white_exes[i]));
    }
// #endif
}

int handle_cmd_add_white_exes(void* data,int size)
{
    u_char c = 'A';
    int rc = -EINVAL;
    u_char* pdata = (u_char*)data;

    if(!data || size <= 0) {
        DEFENSE_LOG_ERROR("invalid add defnese white exe policy\n");
        return rc;
    }

    /*
     *第一个字节表示操作类型
     *A -->表示只添加新记录
     *C --> cleanup and add,表示清理并添加；此时可以有需要添加的路径也可以没有;
            没有需要添加的路径时，表示完全清理;有路径时，需要在先清理再添加
     *D -->删除特定记录
     */
    c = pdata[0];
    --size;
    ++pdata;

    if(size < 0) {
        DEFENSE_LOG_ERROR("invalid size of defense white exe policy\n");
        return rc;
    }

    rc = 0;
    switch(c) {
    case 'A':
    {
        rc = add_white_exe(pdata,size);
    }
    break;
    case 'C': 
    {
        //此处size可以为0
        cleanup_white_exes();
        if(size > 0 && *pdata) {
            rc = add_white_exe(pdata,size);
        }

        //uos的路径无论如何都是要默认加白的
        add_uos_white_exes();
    }
    break;
    case 'D':
    {
        rc = del_white_exe(pdata,size);
    }
    break;
    default:
    {
        DEFENSE_LOG_ERROR("unknow defense white exe policy "
                "action: %c,nvalue: %d\n",
                c,c & 0xff);
    }
    break;
    }

    return rc;
}

int is_defense_white_exe(const char* exe,size_t len)
{
    int rc = 0;
    if(!exe || !*exe) { return rc; }

    //len允许为0,我们自己计算
    if(!len) { len = strlen(exe); }
    if(!len) { return rc; }

    rc = vsec_htable_exist(&white_exes,(void*)exe,len);
    LOG_DEBUG("check %s is in hash table: %s,rc: %d\n",
            exe,white_exes.name,rc);
    return rc;
}

typedef struct {
	char* buf;
	size_t size;//buf大小
	int len;
}ht_walk_ctx_t;

static void ht_walk_cb(void* key,size_t key_len,
					void* data,void* ctx)
{
	size_t n = 0;
	ht_walk_ctx_t* pctx = ctx;
	//one more character for ;
	n = pctx->size - pctx->len - 1;
	n = min(key_len,n);

	memcpy(pctx->buf + pctx->len,key,n);
	pctx->len += n;
	pctx->buf[pctx->len++] = ';';
}

//此处返回实际的长度或错误
int get_defense_white_exes(char* buf,size_t len)
{
	int rc = 0;
	ht_walk_ctx_t ctx;
	
	ctx.len = 0;
	ctx.buf = buf;
	ctx.size = len;
	rc = vsec_htable_walk(&white_exes,
				&ctx,ht_walk_cb);
	if(rc < 0) { return rc; }
	
	//此处返回实际的长度
	rc = ctx.len;
	
	return rc;
}

int defense_policy_init(void)
{
    int rc = 0;
    rc = vsec_htable_init(&white_exes,
                "defense_white_exe",
				NULL,16,
                htable_cmp_fn,
                htable_hash_fn,
                htable_free_fn);
    if(rc == 0) {
        add_uos_white_exes();
    }

    return rc;
}

void defense_policy_uninit(void)
{
    vsec_htable_cleanup(&white_exes);
    vsec_htable_uninit(&white_exes);
}
