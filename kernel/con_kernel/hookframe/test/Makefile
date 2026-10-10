
.PHONY: all clean

DEBUG = 0
PWD := $(shell pwd)
PDIR := $(shell realpath $(PWD)/../)
VER := 1.0.0.0000

ifeq ($(KVER), )
	KVER = $(shell uname -r)
endif

ifeq ($(KPATH), )
	KPATH = /lib/modules/$(KVER)/build
endif

ifeq ($(MACHINE), )
	MACHINE = $(shell uname -m)
endif

#指定模块名
KO_NAME := khookframe
ifneq ($(NAME), )
	KO_NAME := $(NAME)
endif

NOW_TIME = $(shell date +'%Y-%m-%d %H:%M:%S %Z')

EXTRA_CFLAGS := -DDEVICE_VERSION="\"${VER}\""
#全局debug_flag标识,用于控制在运行时开启debug日志
#EXTRA_CFLAGS += -DDEBUG_FLAG
EXTRA_CFLAGS += -DKMOD_NAME="\"${KO_NAME}\""
EXTRA_CFLAGS += -DBUILD_TIME="\"${NOW_TIME}\""
EXTRA_CFLAGS += -DCOMPILER="\"${CC}\""
# EXTRA_CFLAGS += -I$(PWD)/
EXTRA_CFLAGS += -I$(src)/../

ifeq ($(DEBUG), 1)
	EXTRA_CFLAGS += -DDEBUG=1
endif

EXTRA_CFLAGS += -Wno-multichar
EXTRA_CFLAGS += $(PC_DEFINE)


kvd_kernel-objs += main.o
kvd_test-objs += fake_test.o 
kvd_test-objs += syscall_test.o 
#kvd_test-objs += sysfs_test.o 

khf-objs += ../hook/kvd_hook.o 

khf-objs += ../hook/ksyscall_hook.o 
khf-objs +=  ../hook/hook_ksyms.o 
khf-objs +=  ../hook/sysmap.o
khf-objs +=  ../hook/syscall_name.o
khf-objs +=  ../hook/arch/hook_arch.o

kvd_core-objs += ../core/kvd_version.o 
kvd_core-objs += ../core/hook_ops.o
kvd_core-objs += ../core/kvd_blm.o
kvd_core-objs += ../core/kvd_memcache.o 
kvd_core-objs += ../core/kvd_syscalls.o 
kvd_core-objs += ../core/kvd_core.o 
kvd_core-objs += ../core/khookframe.o 


kvd_lsm-objs += ../lsm/kvd_lsm.o
kvd_exec-objs += ../exec/exec_fake.o

kvd_kernel-objs += $(khf-objs)
kvd_kernel-objs += $(kvd_test-objs)

kvd_kernel-objs += $(kvd_lsm-objs)
kvd_kernel-objs += $(kvd_core-objs)
kvd_kernel-objs += $(kvd_sysfs-objs)

kvd_kernel-objs += $(kvd_lsm-objs)
kvd_kernel-objs += $(kvd_exec-objs)
kvd_kernel-objs += $(kvd_fs-objs)

$(KO_NAME)-objs = $(kvd_kernel-objs)
obj-m += $(KO_NAME).o

all:
	make -C $(KPATH) M=$(PWD) modules
	-strip --strip-debug $(KO_NAME).ko
	-mv $(KO_NAME).ko $(KO_NAME).ko_$(KVER)
clean:
	make -C $(KPATH) M=$(PWD) clean
	-rm -f $(KO_NAME).ko_$(KVER)
	-find ../ -name '*.o' -o -name '*.cmd' | xargs rm -f

