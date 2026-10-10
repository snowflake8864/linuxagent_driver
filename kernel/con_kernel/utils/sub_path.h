/*
 *sub_path.h: 2019-09-24 created by qudreams
 *用于处理子目录及子文件查找匹配,不适用于其他
 *此处我们使用的是rb_htable来实现的，使用时要小心
 *此处的功能主要是解决子目录及子文件查找采用链表查找效率不高的问题
 *在使用时有非常严格的限制:
 *1.路径添加时，目录与文件是通过结尾的/来区分的
 *2.添加的路径要是绝对路径，相对路径是不支持的
 */

#ifndef KOSEC_SUB_PATH_H
#define KOSEC_SUB_PATH_H

#include "rb_htable.h"


/*
 *初始化目录rb_htable,rbht is a short-name for red-black hash-table
 *Note!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 *ht-->该参数标识的rb-htable后续只能用来存放目录或存放文件，
 *  因为初始化时的比较函数及hash算法均是针对目录或文件设计的
 */
int vsec_path_rbht_init(struct vsec_rb_htable* ht,
            const char* name,void* ctx);
//支持自定义辅助函数
int vsec_path_rbht_init2(struct vsec_rb_htable *ht,
        const char *name, void *ctx,
        vsec_rb_ht_cmp_fn_t cmp_fn,
        vsec_rb_ht_hash_fn_t hash_fn,
        vsec_rb_ht_free_fn_t free_fn);

//返回值0或大于0的值-->均表示成功,此时是清理的元素个数
//小于0是错误,返回值就是错误码
int vsec_path_rbht_cleanup(struct vsec_rb_htable* ht);
void vsec_path_rbht_uninit(struct vsec_rb_htable* ht);

//调用该函数时：path如果是目录，则一定要在尾部有一个/
//否则是无法正确区分目录或者文件
//path不要求是临时变量，该函数内部会复制该路径并对长度做重新计算
int vsec_path_rbht_insert(struct vsec_rb_htable* ht,
            const char* path,size_t len);
int vsec_path_rbht_delete(struct vsec_rb_htable* ht,
            const char* path,size_t len);
/*
 *判断path是否为ht中标识目录列表中的一个子目录或子文件
 *Note:
 *如果ht中有与path相同的路径，我们也认为匹配成功
 */
int vsec_path_rbht_is_sub(struct vsec_rb_htable* ht,
            const char* path,size_t len);
//判断是否为子目录并返回匹配项
int vsec_path_rbht_sub_and_get(struct vsec_rb_htable *ht,
        const char *path, size_t len,
        void (*cb)(void *data, void *ctx), void *ctx);

//修正路径长度
size_t revise_pathlen(const char *path, size_t len);
//对路径层级做计算
#define MAX_DIR_LEVEL 16
uint32_t calc_path_level(void *key, size_t len);

#endif
