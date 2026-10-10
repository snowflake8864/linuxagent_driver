/*
 *cdev.h: 2019-07-05 created by qudreams
 *support character device
 */
#ifndef KOSEC_CDEV_H
#define KOSEC_CDEV_H

int vsec_cdev_init(const char* cdev_name);
void vsec_cdev_uninit(void);
const char* vsec_cdev_name(void);

struct vsec_pack_stats;
int vsec_cdev_get_stats(struct vsec_pack_stats* st_in,
					struct vsec_pack_stats* st_out);

#endif
