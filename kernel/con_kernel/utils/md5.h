#ifndef KOSEC_MD5_H
#define KOSEC_MD5_H

#include <linux/types.h>

typedef struct {
	uint64_t bytes;
	uint32_t a, b, c, d;
	u_char buffer[64];
} vsec_md5_t;

void vsec_md5_init(vsec_md5_t *ctx);
void vsec_md5_update(vsec_md5_t *ctx, const void *data, size_t size);
void vsec_md5_final(u_char result[16], vsec_md5_t *ctx);
/*
 *计算数据的MD5值，计算出来的MD5值不转化为16进制
 */
void vsec_md5_data(u_char *md5, const void *data, u_int len);

#endif