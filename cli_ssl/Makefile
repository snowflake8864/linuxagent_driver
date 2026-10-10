# 原Makefile内容保持不变...
DEBUG=1
STATIC=0
CC=gcc
CXX=g++
ARCH=$(shell uname -m)
LOW_VERSION_UDEV=0

###########################################################
#CPPFLAGS += -Werror
CPPFLAGS += -Wno-deprecated-declarations

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

#LIBDIR = none

LIBS += ${ROOTDIR}/common/dependlibs/Ubuntu_openssl/lib/libssl.a
LIBS += ${ROOTDIR}/common/dependlibs/Ubuntu_openssl/lib/libcrypto.a
LIBS += -ldl -lrt -lpthread -lz 
###########################################################

# 修改目标文件定义
SERVER_OBJS = server.o
CLIENT_OBJS = client.o
AGENT_CLI_OBJS = agent_cli.o
AGENT_CLI_CLIENT_OBJS = agent_cli_client.o

# 可执行程序目标
TARGETS = ${ROOTDIR}/cli_ssl/server ${ROOTDIR}/cli_ssl/client ${ROOTDIR}/cli_ssl/agent_cli ${ROOTDIR}/cli_ssl/MagicArmor_cli


# 添加生成规则
all: $(TARGETS)

${ROOTDIR}/cli_ssl/server: $(SERVER_OBJS)
	$(CXX) $(CPPFLAGS) -o $@ $^ $(LIBDIR) $(LIBS)

${ROOTDIR}/cli_ssl/client: $(CLIENT_OBJS)
	$(CXX) $(CPPFLAGS) -o $@ $^ $(LIBDIR) $(LIBS)
${ROOTDIR}/cli_ssl/agent_cli: $(AGENT_CLI_OBJS)
	$(CXX) $(CPPFLAGS) -o $@ $^ $(LIBDIR) $(LIBS)
${ROOTDIR}/cli_ssl/MagicArmor_cli: $(AGENT_CLI_CLIENT_OBJS)
	$(CXX) $(CPPFLAGS) -o $@ $^ $(LIBDIR) $(LIBS)

# 目标文件编译规则
server.o: server.cpp
	$(CXX) $(CPPFLAGS) -c $< -o $@

client.o: client.cpp
	$(CXX) $(CPPFLAGS) -c $< -o $@

agent_cli.o: agent_cli.cpp
	$(CXX) $(CPPFLAGS) -c $< -o $@

agent_cli_client.o: agent_cli_client.cpp
	$(CXX) $(CPPFLAGS) -c $< -o $@
%.o: %.c
	$(CC) $(CPPFLAGS) -c $< -o $@

.PHONY: clean distclean
clean:
	rm -f $(TARGET_OBJS)
	rm -f ${ROOTDIR}/cli_ssl/server ${ROOTDIR}/cli_ssl/client ${ROOTDIR}/cli_ssl/agent_cli ${ROOTDIR}/cli_ssl/MagicArmor_cli

distclean:
	rm -f $(TARGET_OBJS)


