#ifndef KOSEC_MM_CDEV_H
#define KOSEC_MM_CDEV_H

/*
 *kernel tian qing mmap char-device
 *mmc is a short-name for mmap char-device
 */

#include <linux/in6.h>
#include <linux/timer.h>
#include <linux/timex.h>
#include <linux/rtc.h>
#include <linux/version.h>


/* *********************************** */


/*
 * packet socket options
 */
typedef struct vsec_mmc_s {
    void* priv;//Note: must be first member

	atomic_t		ref;
	/* Ring  page block */
	struct mutex	pg_vec_lock;
	spinlock_t		lock;
	struct vsec_pack_stats st_in; //from user-space
	struct vsec_pack_stats st_out; //to user-space
	wait_queue_head_t waits;
	char **			pg_vec;
	unsigned int	head;
	unsigned int    frames_per_block;
	unsigned int	frame_size;
	unsigned int	frame_max;

	unsigned int    pg_vec_order;
	unsigned int	pg_vec_pages;
	unsigned int	pg_vec_len;
}vsec_mmc_t;


void vsec_mmc_init(void);
void vsec_mmc_exit(void);
const char* vsec_mmc_name(void);
int vsec_mmc_get_stats(struct vsec_pack_stats* st_in,
				struct vsec_pack_stats* st_out);

#endif /* KOSEC_MM_CDEV_H */
