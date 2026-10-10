
.PHONY: all simple clean

DEBUG = 0
VER = 2.0.0.4685
PWD = $(shell pwd)
KVDDIR=hookframe
KVD_MKF=$(KVDDIR)/Makefile.in
SPEC_VERSION_BUILD=0
ADM_VERSION_BUILD=0
LSM_VERSION_BUILD=0
USE_CR0_ASM_SYNTAX=0
CLOSE_LSM_FORCED=0
CR0_ASM_SYNTAX_BUILD=0

ifeq ($(KVER), )
	KVER = $(shell uname -r)
endif

ifeq ($(KPATH), )
	KPATH = /lib/modules/$(KVER)/build
else
	segments := $(patsubst %/build,%,$(KPATH))
	KVER = $(lastword $(subst /, ,$(segments)))
endif
ifeq ($(MACHINE), )
	MACHINE = $(shell uname -m)
endif

CR0_ASM_SYNTAX_VERSIONS = \
    4.18.0-553.el8_10.x86_64 \
    4.19.90-2312.1.0.0255.oe2003sp4.x86_64

ifeq ($(filter $(KVER), $(CR0_ASM_SYNTAX_VERSIONS)), $(KVER))
    CR0_ASM_SYNTAX_BUILD=1
endif


#LSM_VERSIONS = \
#    4.18.0-553.el8_10.x86_64 \
#    4.19.90-2312.1.0.0255.oe2003sp4.x86_64
LSM_VERSIONS = \
6.6.0-32.7.v2505.ky11.x86_64 \
6.6.0-145.0.2.143.oe2403sp2.x86_64  \
5.15.0-164-generic \
5.15.0-139-generic 

ifeq ($(filter $(KVER), $(LSM_VERSIONS)), $(KVER))
    LSM_VERSION_BUILD=1
endif

CLOSE_LSM_FORCED_VERSIONS = \
    4.19.90-89.11.v2401.ky10.x86_64 \
    4.19.90-89.11.v2401.ky10.aarch64 \
    4.19.90-25.10.v2101.ky10.aarch64 \
    4.19.90-25.2.v2101.gfb01.ky10.aarch64\
    4.19.90-89.40.v2401.ky10.x86_64\
    4.19.90-52.23.v2207.gfb01.ky10.aarch64 

ifeq ($(filter $(KVER), $(CLOSE_LSM_FORCED_VERSIONS)), $(KVER))
     CLOSE_LSM_FORCED=1
endif



# List of KVER versions that should set SPEC_VERSION_BUILD=1
SPEC_VERSIONS_ONE = \
    4.18.0-540.el8.x86_64 \
    4.18.0-425.19.2.el8_7.x86_64 \
    4.18.0-477.27.1.el8_8.x86_64 \
    4.18.0-477.21.1.el8_8.x86_64 \
    4.18.0-513.18.1.el8_9.x86_64 \
    4.18.0-553.5.1.el8_10.x86_64 \
    4.18.0-477.27.2.el8_8.x86_64 \
    4.18.0-477.36.1.0.1.an8.x86_64\
    4.18.0-372.9.1.an8.x86_64\
    4.18.0-553.el8_10.x86_64\
    4.18.0-372.32.1.el8_6.x86_64\
    4.18.0-553.109.1.el8_10.x86_64\
    4.18.0-372.9.1.el8.x86_64
# List of KVER versions that should set SPEC_VERSION_BUILD=1
SPEC_VERSIONS_TWO = \
    5.14.0-70.30.1.el9_0.x86_64 \
    5.14.0-70.26.1.el9_0.x86_64

SPEC_VERSIONS_THREE = \
    5.10.134-17.1.al8.x86_64

SPEC_VERSIONS_FOUR = \
    5.10.0-9-generic \
    5.10.0-15-generic

SPEC_VERSIONS_FIVE = \
    5.10.134-18.an8.x86_64
SPEC_VERSIONS_SIX = \
    6.5.6-300.fc39.x86_64

ifeq ($(filter $(KVER), $(SPEC_VERSIONS_ONE)), $(KVER))
    SPEC_VERSION_BUILD=1
endif


ifeq ($(filter $(KVER), $(SPEC_VERSIONS_TWO)), $(KVER))
    SPEC_VERSION_BUILD=2
endif


ifeq ($(filter $(KVER), $(SPEC_VERSIONS_THREE)), $(KVER))
    SPEC_VERSION_BUILD=3
endif

ifeq ($(filter $(KVER), $(SPEC_VERSIONS_THREE)), $(KVER))
    SPEC_VERSION_BUILD=3
endif
ifeq ($(filter $(KVER), $(SPEC_VERSIONS_FOUR)), $(KVER))
    SPEC_VERSION_BUILD=4
endif
ifeq ($(filter $(KVER), $(SPEC_VERSIONS_FIVE)), $(KVER))
    SPEC_VERSION_BUILD=5
endif
ifeq ($(filter $(KVER), $(SPEC_VERSIONS_SIX)), $(KVER))
    SPEC_VERSION_BUILD=6
endif







SRC_PATH := /root/code/code/linux/kernel/$(KVER)/source

ifeq ($(KVER), 5.10.0-29-amd64)  
    DST_PATH := /usr/src/linux-headers-5.10.0-29-common
endif  

ifeq ($(KVER), 4.19.0-23-amd64)  
    DST_PATH := /usr/src/linux-headers-4.19.0-23-common
endif  


ifeq ($(KVER), 6.1.0-21-amd64)  
    DST_PATH := /usr/src/linux-headers-6.1.0-21-common
else

endif  
ifeq ($(KVER), 6.1.0-22-amd64)  
    DST_PATH := /usr/src/linux-headers-6.1.0-22-common
endif  

ifeq ($(DST_PATH), )  
    DST_PATH := /usr/src/linux-headers-$(KVER)-common
endif

NOW_TIME = $(shell date +'%Y-%m-%d %H:%M:%S %Z')

EXTRA_CFLAGS := -DDEVICE_VERSION="\"${VER}\""
EXTRA_CFLAGS += -DDEBUG_FLAG
EXTRA_CFLAGS += -DBUILD_TIME="\"${NOW_TIME}\""
EXTRA_CFLAGS += -DCOMPILER="\"${CC}\""
EXTRA_CFLAGS += -I$(src)/
EXTRA_CFLAGS += -I$(src)/$(KVDDIR)/
EXTRA_CFLAGS += -I$(src)/../../common/kernel/
EXTRA_CFLAGS += -DSPEC_VERSION_BUILD=${SPEC_VERSION_BUILD}  # 添加SPEC_VERSION_BUILD
EXTRA_CFLAGS += -DLSM_VERSION_BUILD=${LSM_VERSION_BUILD}  # 添加LSM_VERSION_BUILD
EXTRA_CFLAGS += -DCR0_ASM_SYNTAX_BUILD=${CR0_ASM_SYNTAX_BUILD}
EXTRA_CFLAGS += -DCLOSE_LSM_FORCED=${CLOSE_LSM_FORCED}  # 添加CLOSE_LSM_FORCED


ifeq ($(DEBUG), 1)
	EXTRA_CFLAGS += -DDEBUG=1
endif


#指定模块名
KO_NAME := osec_base
ifneq ($(NAME), )
	KO_NAME := $(NAME)
endif


EXTRA_CFLAGS += -pie -Wno-multichar
EXTRA_CFLAGS += $(PC_DEFINE)


vd_kernel-objs += main.o
vd_kernel-objs += stack/stack.o

include abnormal/Makefile.in
include kthread/Makefile.in
include hook/Makefile.in
include notify/Makefile.in
include utils/Makefile.in
include core/Makefile.in
include clientexit/Makefile.in
include netlink/Makefile.in
include cdev/Makefile.in
include sysfs/Makefile.in
include fs/Makefile.in
include defense/Makefile.in
include acsm/Makefile.in
include dpi/Makefile.in
include rules/Makefile.in
include iptree/Makefile.in
include forward/Makefile.in
include hcache/Makefile.in
include process_audit/Makefile.in
include docker_audit/Makefile.in
include md5hash/Makefile.in
include ref_manager/Makefile.in
include log_manager/Makefile.in

include $(KVD_MKF)

$(KO_NAME)-objs = $(vd_kernel-objs) $(kvd_kernel-objs) 
obj-m += $(KO_NAME).o

JOBS=-j$(shell awk 'BEGIN{print ('2'*'$(shell nproc)')}')
#create-symlink:  
#	@if [ ! -L "$(LINK_TARGET)" ]; then \
		echo "Creating symlink: $(LINK_TARGET) -> $(KSRC)"; \
		ln -sf $(KSRC) $(LINK_TARGET); \
	fi  
all: 
	echo "$(KVER)"
	ln -sf $(SRC_PATH) $(DST_PATH)
	make $(JOBS) -I$(PWD) -C $(KPATH) M=$(PWD) modules
	-rm symbols.txt
	-$(KPATH)/scripts/mod/modpost -m -a -i $(KPATH)/Module.symvers -I $(PWD)/Module.symvers  -o $(PWD)/Module.symvers   $(PWD)/$(KO_NAME).o 2>symbols.txt
	-awk '{print $0}' $(PWD)/symbols.txt
	a=`awk '{print $0}' $(PWD)/symbols.txt  | grep "undefined" | grep -v "module_layout" | grep -v "struct_module" |wc -l`;echo $${a};\
	if [ $${a} -gt 0 ];\
	then\
        echo "kernel Symbol not exported";\
	strip --strip-debug $(KO_NAME).ko;\
	cp $(KO_NAME).ko output/$(KO_NAME).ko-$(KVER);\
	rm -f $(DST_PATH); \
        exit 1;\
	fi
ifeq ($(DEBUG), 1)
	-cp $(KO_NAME).ko output/$(KO_NAME).ko-$(KVER)
else
	-strip --strip-debug $(KO_NAME).ko
	-cp $(KO_NAME).ko $(KO_NAME).ko-$(KVER)
	-nm $(KO_NAME).ko | awk '{if ($$2 == "t" || $$2 == "b" || $$2 == "d" || $$2 == "r") {print $$3}}' | egrep -v '^\..*' > static.txt
	-nm $(KO_NAME).ko | awk '{if ($$2 == "B" || $$2 == "T" || $$2 == "D" || $$2 == "R") {print $$3}}' | egrep -v '^\..*' | xargs -I {} bash -c 'printf {}" ";echo {} | md5sum | egrep -o "^.{16}" | head -n 1' | awk '{print $$1" "$$2}' > syms.txt
	-objcopy --strip-symbols=static.txt --redefine-syms=syms.txt $(KO_NAME).ko output/$(KO_NAME).ko-$(KVER) 2>errors.txt
	-if [ ! -f $(PWD)/output/$(KO_NAME).ko-$(KVER) ];\
	then\
		echo "$(KO_NAME).ko-$(KVER) Encryption failed,again";\
		awk -F '`' '{print $$2}'  $(PWD)/errors.txt | awk -F "'" '{print $$1'} | xargs -I {} sed -r -i 's/^{}$///g' static.txt ;\
		objcopy --strip-symbols=static.txt --redefine-syms=syms.txt $(KO_NAME).ko output/$(KO_NAME).ko-$(KVER);\
	else\
		echo "$(KO_NAME).ko-$(KVER) Encrypted successfully";\
	fi
	-rm static.txt syms.txt errors.txt
endif
	-rm symbols.txt
	-rm -f $(DST_PATH)
simple: 
	echo "$(KVER)"
	ln -sf $(SRC_PATH) $(DST_PATH)
	make $(JOBS) -I$(PWD) -C $(KPATH) M=$(PWD) modules
	-strip --strip-debug $(KO_NAME).ko
	-cp $(KO_NAME).ko $(KO_NAME).ko-$(KVER)
	-cp $(KO_NAME).ko output/$(KO_NAME).ko-$(KVER)
	-rm -f $(DST_PATH)


clean:
	# -make -C ad_fake/ clean
	make -I$(PWD) -C $(KPATH) M=$(PWD) clean
	-rm -f $(KO_NAME).ko-$(KVER)
	-rm -f output/$(KO_NAME).ko-$(KVER)
	-rm -f $(DST_PATH)
