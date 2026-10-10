/*
 *pks_wp.h: 2020-3-14 created by qudreams
 *
 * 用于处理PKS项目中澜起安全内存机制开启后
 * 无法替换系统调用的问题
 */
#ifndef KOSEC_PKS_WP_H
#define KOSEC_PKS_WP_H

#include <linux/types.h>

bool is_pks_wp_enabled(void);
void pks_wp_init(void);
void pks_wp_uninit(void);
int pks_wp_set(unsigned long addr,
			void* data,size_t len);
int pks_wp_reset(unsigned long addr,
			void* data,size_t len);

#endif
