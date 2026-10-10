#include <linux/module.h>
#include <linux/version.h>
#include <linux/module.h>

#if 0
//需要注意的是mips64 3.10.0版本的系统上没有UTS_VERSION
//另外suse 3.12.0版本的内核上连generated/compile.h文件都没有
//我们此处为了处理方便全部限定只有4.0.0以上的内核才引入下面的文件
#if ((!defined(CONFIG_MACH_LOONGSON3)  && !defined(CONFIG_X86_32)) && \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)))

    #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19)
        #include <generated/compile.h> //for UTS_VERSION
    #else
        #include <linux/compile.h> //UTS_VERSION
    #endif
#endif
#else
#ifndef UTS_VERSION
    #define SAFE_UTS_VERSION init_uts_ns.name.release
#else
    #define SAFE_UTS_VERSION UTS_VERSION
#endif

#endif
#include "core/kvd_core.h"
#include "kvd_version.h"

#ifndef DEVICE_VERSION
#define DEVICE_VERSION ""
#endif

#ifndef COMPILER
#define COMPILER ""
#endif


#ifndef BUILD_TIME
#define BUILD_TIME ""
#endif 

#ifndef UTS_VERSION
#define UTS_VERSION ""
#endif


struct vsec_mod_ver {
	char name[64];
	char version[32];
	char buildtime[32];
}__attribute__((packed));

struct vsec_mod_ver vd_mod_version 
__attribute__((section(".vd_mod_version"))) = 
{
	.name = KBUILD_MODNAME,
	.version = DEVICE_VERSION,
	.buildtime = BUILD_TIME,
};


const char vd_kmod_vermagic[128] 
__attribute__((section(".vd_kmod_vermagic")))
= { UTS_RELEASE" "UTS_VERSION };

static const char mod_version[] = {
						"version: "DEVICE_VERSION"\n"
						"kernel-version: "UTS_RELEASE" "UTS_VERSION"\n"
						"compiler: "COMPILER" "__VERSION__"\n"
						"build-time: "BUILD_TIME"\n"
					};

const char* kvd_get_version(void)
{
	return mod_version;
}
								 
