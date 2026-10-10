#ifndef KVD_BLM_H
#define KVD_BLM_H

#include <linux/types.h>
#include "kvd_core.h"
//简易布隆过滤器
//简易布隆过滤器
typedef struct {
    uint64_t hmin; //最小值
    uint64_t hmax; //最大值
}kvd_blm_hval_t;

uint64_t kvd_calc_blm_hval(const char* data,
                            size_t len);
bool kvd_check_blm_hval(const char* data,size_t len,
                        const kvd_blm_hval_t* blm_hval);
void kvd_array_blm_hval(const char* arr[],size_t size,
                        kvd_blm_hval_t* blm_hval);

#endif
