#include <linux/types.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/time.h>
#include <linux/version.h>
#include <linux/utsname.h>

//此处的检查只针对Uos,申威，龙芯平台
//所以我们使用这个宏来区分uos平台与其他平台
//另外，需要注意的是mips64 3.10.0版本的系统上没有UTS_VERSION
#if defined(CONFIG_SECURITY_ELFVERIFY) || \
    defined(CONFIG_ARM64) || \
    defined(CONFIG_SW) || \
    defined(CONFIG_KYLINOS_DESKTOP) || defined(CONFIG_KYLINOS_SERVER) || \
    (defined(CONFIG_MACH_LOONGSON3) && (LINUX_VERSION_CODE > KERNEL_VERSION(3,10,0)))

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19)
#include <generated/compile.h> //for UTS_VERSION
#else
#include <linux/compile.h> //UTS_VERSION
#endif
#endif

#ifndef UTS_VERSION
#define HAS_UTS_VERSION 0
#else
#define HAS_UTS_VERSION 1
#endif

#include "gnHead.h"
#include "abnormal.h"
#include "core/kvd_core.h"
#include "utils/utils.h"

#define LOAD_FAIL_STATUS "/opt/.osec_base_status"
#define LOAD_TIMESPEC_PATH "/opt/."KOSEC_SYSFS_NAME"kernel_timespec"
#define LOAD_CHECK_FIRST "/dev/."KOSEC_SYSFS_NAME"kernel_first"
#define TIME_OFFSET 300
#define ERROR_TIMES 3

static void do_write_abnormality(struct file* fp,
					u_long err_time,long err_count)
{
	loff_t pos = 0;
	char str[64] = {0};
	int nlen = kvd_snprintf(str, sizeof(str),
				"%lu %ld",err_time,err_count);
	kvd_kernel_write(fp,str,nlen,&pos);
}

static void clean_abnormality(struct file* fp)
{
	loff_t pos = 0;
	char str[64] = {0};
	
	kvd_kernel_write(fp,str,sizeof(str),&pos);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
struct tm {
    /*
     * the number of seconds after the minute, normally in the range
     * 0 to 59, but can be up to 60 to allow for leap seconds
     */
    int tm_sec;
    /* the number of minutes after the hour, in the range 0 to 59*/
    int tm_min;
    /* the number of hours past midnight, in the range 0 to 23 */
    int tm_hour;
    /* the day of the month, in the range 1 to 31 */
    int tm_mday;
    /* the number of months since January, in the range 0 to 11 */
    int tm_mon;
    /* the number of years since 1900 */
    long tm_year;
    /* the number of days since Sunday, in the range 0 to 6 */
    int tm_wday;
    /* the number of days since January 1, in the range 0 to 365 */
    int tm_yday;
};
#endif
/* xxxx-xx-xx xx:xx:xx xxx */
#ifndef BUILD_TIME
#define BUILD_TIME ""
#endif
static int may_abnormal(struct file* fp,const char* ts_str,u_long now_sec)
{
	int rc = 0;
	long error_count = 0;
	u_long scord_time = 0;
	u_long time_offset = 0;	
	char scord_time_buf[32] = {0};
	char error_count_buf[16] = {0};	
    u_long build_time = 0;

    //运行时间小于编译时间的,认为系统时间异常,不再检查
    struct tm tm;
    char *pend = NULL;
    tm.tm_year = simple_strtol(BUILD_TIME, &pend, 10);
    if (tm.tm_year <= 0 || *pend != '-') return rc;
    tm.tm_mon = simple_strtol(pend+1, &pend, 10);
    if (*pend != '-') return rc;
    tm.tm_mday = simple_strtol(pend+1, &pend, 10);
    if (*pend != ' ') return rc;
    tm.tm_hour = simple_strtol(pend+1, &pend, 10);
    if (*pend != ':') return rc;
    tm.tm_min = simple_strtol(pend+1, &pend, 10);
    if (*pend != ':') return rc;
    tm.tm_sec = simple_strtol(pend+1, &pend, 10);
    if (*pend != ' ') return rc;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
    build_time = mktime64(tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
#else
    build_time = mktime(tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
#endif
    build_time -= 8*60*60;//东8区时间
    if (now_sec < build_time) {
        LOG_ERROR("abnormal check skipped due to time error: now=%lu, build_time=%lu\n", now_sec, build_time);
        return rc;
    }

	sscanf(ts_str, "%s %s", scord_time_buf, error_count_buf);
	scord_time = simple_strtoul(scord_time_buf, NULL, 10);	
	error_count = simple_strtol(error_count_buf, NULL, 10);	
	//这种情况会出现在系统时间被修改时,
	//我们直接使用当前时间赋值即可
	if(now_sec < scord_time) { scord_time = now_sec; }
	time_offset = now_sec - scord_time;
		
	LOG_INFO("abnormal_check_init:current_time=%lu,scord_time=%lu, time_offset = %lu \n",
			now_sec, scord_time, time_offset);
	
	if (TIME_OFFSET > time_offset) {
		error_count++;
		if (ERROR_TIMES < error_count) {
			rc = -1;
		}
		clean_abnormality(fp);
		kvd_fsync(fp,0);

		do_write_abnormality(fp,now_sec,error_count);
	} else {
		clean_abnormality(fp);
	}

	return rc;
}

extern struct new_utsname* get_init_utsname(void);
#if 0
static int check_utsname(void)
{
	int rc = 0;
	
	//此处的检查只针对Uos,目前只有Uos上有这个宏，
	//所以我们使用这个宏来区分uos平台与其他平台
#if defined(CONFIG_SECURITY_ELFVERIFY) || \
    defined(CONFIG_ARM64) || \
    defined(CONFIG_SW) || \
    defined(CONFIG_KYLINOS_DESKTOP) || defined(CONFIG_KYLINOS_SERVER) || \
    (defined(CONFIG_MACH_LOONGSON3) && (LINUX_VERSION_CODE > KERNEL_VERSION(3,10,0)))

	struct new_utsname* putsname = NULL;
	
	putsname = get_init_utsname();

    //kylin系统上的UTS_VERSION有可能跟运行时的内核不一样
    //这是在kylin v10 PKS-202007071的版本上发现的问题!!!!!!!
    //针对kylin的系统我们只检验UTS_RELEASE
	if(putsname && 
	   (strcmp(putsname->release,UTS_RELEASE)  
    #if (!defined(CONFIG_KYLINOS_DESKTOP)) && \
        (!defined(CONFIG_KYLINOS_SERVER))
       || strcmp(putsname->version,UTS_VERSION)
    #endif
       )) 
	{
		LOG_ERROR("we expect kernel is: %s %s,"
			"but current kernel is: %s %s;"
			"we don't support this situation\n",
			UTS_RELEASE,UTS_VERSION,
			putsname->release,putsname->version);

		rc = -EPERM;
	}
#endif
	return rc;	
}
#else
static int check_utsname(void)
{
    int rc = 0;

#if defined(CONFIG_SECURITY_ELFVERIFY) || \
    defined(CONFIG_ARM64) || \
    defined(CONFIG_SW) || \
    defined(CONFIG_KYLINOS_DESKTOP) || defined(CONFIG_KYLINOS_SERVER) || \
    (defined(CONFIG_MACH_LOONGSON3) && (LINUX_VERSION_CODE > KERNEL_VERSION(3,10,0)))

    struct new_utsname *putsname = get_init_utsname();

    if (!putsname) {
        LOG_ERROR("Failed to get init_utsname\n");
        return -EPERM;
    }

    // 检查 UTS_RELEASE 总是需要的
    if (strcmp(putsname->release, UTS_RELEASE) != 0) {
        goto mismatch;
    }

    // 仅在支持 UTS_VERSION 时才检查 version 字段
#if HAS_UTS_VERSION
#if !defined(CONFIG_KYLINOS_DESKTOP) && !defined(CONFIG_KYLINOS_SERVER)
    if (strcmp(putsname->version, UTS_VERSION) != 0) {
        goto mismatch;
    }
#endif
#endif

    return 0;

mismatch:
    LOG_ERROR("we expect kernel is: %s %s,"
              "but current kernel is: %s %s;"
              "we don't support this situation\n",
#if HAS_UTS_VERSION
              UTS_RELEASE, UTS_VERSION,
#else
              UTS_RELEASE, "(UTS_VERSION unavailable)",
#endif
              putsname->release,
#if HAS_UTS_VERSION
              putsname->version
#else
              "(unknown)"
#endif
    );
    rc = -EPERM;
#endif 

    return rc;
}
#endif

int abnormal_check_time_init(void)
{
	int rc = 0;
	loff_t pos = 0;
	u_long now_sec = 0;
	char ts_str[64] = {0};
	struct file *fp = NULL;

	now_sec = vsec_get_seconds();

	fp = filp_open(LOAD_TIMESPEC_PATH, O_RDWR|O_CREAT, 0755);
	if (IS_ERR(fp)) {
		LOG_ERROR("abnormal_check_init:open %s fail \n", LOAD_TIMESPEC_PATH);
		return rc;
	}

    kvd_kernel_read(fp,ts_str,sizeof(ts_str) - 1,&pos);
	//未读取到数据或者读取的全部是空(\0)
	//此处不要使用kvd_kernel_read的返回值判断
	//因为我们在clean_abnormality中写入了64字节的\0
	if (ts_str[0] == '\0') {
		do_write_abnormality(fp,now_sec,0);
	} else {
		rc = may_abnormal(fp,ts_str,now_sec);
	}
	kvd_fsync(fp, 0);
	filp_close(fp, NULL);

	if (rc < 0) {
		LOG_INFO("Warning: abnormal checker triggered: "
			"the kernel may be crashed beyond %d times in %d seconds\n",
			ERROR_TIMES,TIME_OFFSET);
	}

	return rc;
}

//内核加载异常处理这块做判断,首次安装,重启进行异常检查
//其余不再检查
int abnormal_check_init(void)
{
	int rc = 0;
	struct file *fp = NULL;

	//先检查发行版本
	rc = check_utsname();
	if(rc) { return rc; }
	//打开成功,升级或拉取模块,不走异常检查内核
	fp = filp_open(LOAD_CHECK_FIRST, O_RDWR, 0755);
	if (IS_ERR(fp)) {
		rc = abnormal_check_time_init();

		fp = filp_open(LOAD_CHECK_FIRST, O_CREAT, 0755);
		if (IS_ERR(fp))	{
			LOG_ERROR("abnormal_check_first_load:creat %s fail \n", LOAD_CHECK_FIRST);
			return rc;
		}
	}
	//文件打开成功,不走上面逻辑,关句柄
	//文件打开失败,认为没有文件,走异常检查;然后创建文件,失败直接return;创建成功,关句柄
	filp_close(fp, NULL);

	return rc;
}

void abnormal_check_exit(void)
{
	return;
}

int abnormal_set_fail_status(int stat)
{
	int rc = 0;
	loff_t pos = 0;
	struct file *fp = NULL;
	char str[16] = {0};
	fp = filp_open(LOAD_FAIL_STATUS, O_RDWR, 0755);
	if (IS_ERR(fp)) {
		LOG_ERROR("abnormal_set_fail_status:open %s fail \n", LOAD_FAIL_STATUS);
		return rc;
	}
	int nlen = kvd_snprintf(str, sizeof(str),
				"%u",stat);
	kvd_kernel_write(fp,str,nlen,&pos);

	kvd_fsync(fp, 0);
	filp_close(fp, NULL);
	return rc;
}

