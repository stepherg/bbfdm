CC ?= gcc
PROG = bbf_configd
OBJS = src/ubus/bbf_config.o src/ubus/utils.o
ACTIVE-PORT = active-port
ACTIVE-PORT_OBJS = src/ubus/active-port.o

PROG_CFLAGS = $(CFLAGS) -Wall -Werror
PROG_LDFLAGS = $(LDFLAGS)
PROG_LIBS += -luci -lubus -lubox -lblobmsg_json

INSTALL_DIR = /usr/sbin
	
%.o: %.c
	$(CC) $(PROG_CFLAGS) $(FPIC) -c -o $@ $<

.PHONY: all clean install

all: $(PROG) $(ACTIVE-PORT)
	
$(PROG): $(OBJS)
	$(CC) $(PROG_LDFLAGS) -o $@ $^ $(PROG_LIBS)

$(ACTIVE-PORT): $(ACTIVE-PORT_OBJS)
	$(CC) $(PROG_LDFLAGS) -o $@ $^ $(PROG_LIBS)

clean:
	rm -f $(PROG)
	rm -f $(ACTIVE-PORT)

install: $(PROG) $(ACTIVE-PORT)
	install -m 0755 $(PROG) $(INSTALL_DIR)
	install -m 0755 $(ACTIVE-PORT) $(INSTALL_DIR)
