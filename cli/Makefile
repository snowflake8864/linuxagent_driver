DEBUG=1
STATIC=0
CC=gcc
CXX=g++
ARCH=$(shell uname -m)
LOW_VERSION_UDEV=0

###########################################################
#CPPFLAGS += -Werror
CPPFLAGS += -Wno-deprecated-declarations
CPPFLAGS += -fPIC -Wall

ifeq ($(DEBUG), 1)
        CPPFLAGS += -g3 -ggdb3 -DDEBUG
else
        CPPFLAGS += -g3 -O3 -Os -DNDEBUG
endif

###########################################################
ROOTDIR = ../

INCPATH += -I${ROOTDIR}/common/dependlibs/Ubuntu_openssl/include/
CPPFLAGS += $(INCPATH)

###########################################################
LIBS += -Wl,--as-needed


LIBS += ${ROOTDIR}/common/dependlibs/Ubuntu_openssl/lib/libssl.a
LIBS += ${ROOTDIR}/common/dependlibs/Ubuntu_openssl/lib/libcrypto.a


###########################################################

# 每个可执行程序的目标文件
AGENT_CLI_OBJS = agent_cli.o
SERVER_OBJS = server.o
CLIENT_OBJS = client.o

# 所有目标文件
TARGET_OBJS = $(AGENT_CLI_OBJS) $(SERVER_OBJS) $(CLIENT_OBJS)

# 可执行程序目标
TARGETS = ${ROOTDIR}/cli/agent_cli ${ROOTDIR}/cli/server ${ROOTDIR}/cli/client

###########################################################

# 默认目标：编译所有可执行程序
all: $(TARGETS)

# 规则：链接生成 agent_cli
${ROOTDIR}/cli/agent_cli: $(AGENT_CLI_OBJS)
	$(CXX) $(CPPFLAGS) -o $@ $(AGENT_CLI_OBJS) $(LIBS)

# 规则：链接生成 server
${ROOTDIR}/cli/server: $(SERVER_OBJS)
	$(CXX) $(CPPFLAGS) -o $@ $(SERVER_OBJS) $(LIBS)

# 规则：链接生成 client
${ROOTDIR}/cli/client: $(CLIENT_OBJS)
	$(CXX) $(CPPFLAGS) -o $@ $(CLIENT_OBJS) $(LIBS)

# 编译规则：从 .c 文件生成 .o 文件
%.o: %.c
	$(CC) $(CPPFLAGS) -c $< -o $@

.PHONY: clean distclean
clean:
	rm -f $(TARGET_OBJS)
	rm -f ${ROOTDIR}/cli/agent_cli ${ROOTDIR}/cli/server ${ROOTDIR}/cli/client

distclean:
	rm -f $(TARGET_OBJS)

