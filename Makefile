CC = cc
Y = yacc

PROG = serverstatd
OBJS = serverstatd.o log.o icmp.o icmp_host.o y.tab.o

TARGET =

# Clear flags
CFLAGS =
LDFLAGS =

CFLAGS += -Wall -Werror -O0 -g
CFLAGS += -I. -Icompat

#
# Mac OS X support
#
ifeq ($(TARGET),macosx)
CFLAGS += -DMACOSX_SUPPORT

# Look for macports headers
CFLAGS += -I/opt/local/include
LDFLAGS += -L/opt/local/lib

# Compile IMSG
CFLAGS += -Iimsg
OBJS += imsg/imsg.o imsg/imsg-buffer.o
endif

#
# GNU/Linux support
#
ifeq ($(TARGET),linux)
CFLAGS += -DLINUX_SUPPORT

# Compile strlcpy and strlcat
OBJS += compat/strlcpy.o compat/strlcat.o

# Compile IMSG
CFLAGS += -Iimsg
OBJS += imsg/imsg.o imsg/imsg-buffer.o
endif

LDFLAGS += -levent

.PHONY: clean

all: ${PROG}

y.tab.c:
	${Y} parse.y

${PROG}: ${OBJS}
	${CC} ${CFLAGS} ${OBJS} ${LDFLAGS} -o $@

%.c: %.o
	${CC} ${CFLAGS} $< -c -o $@

clean:
	rm -f -- ${PROG} ${OBJS} y.tab.c
