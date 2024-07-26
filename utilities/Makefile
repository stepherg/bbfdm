CC ?= gcc
PROG = bbf_configd
OBJS = src/ubus/bbf_config.o src/ubus/utils.o

PROG_CFLAGS = $(CFLAGS) -Wall -Werror
PROG_LDFLAGS = $(LDFLAGS)
PROG_LIBS += -luci -lubus -lubox -lblobmsg_json

INSTALL_DIR = /usr/sbin
	
%.o: %.c
	$(CC) $(PROG_CFLAGS) $(FPIC) -c -o $@ $<

.PHONY: all clean install

all: $(PROG)
	
$(PROG): $(OBJS)
	$(CC) $(PROG_LDFLAGS) -o $@ $^ $(PROG_LIBS)

clean:
	rm -f $(PROG)

install: $(PROG)
	install -m 0755 $(PROG) $(INSTALL_DIR)
