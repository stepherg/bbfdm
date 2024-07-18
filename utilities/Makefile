CC ?= gcc
ACTIVE-PORT = active-port
ACTIVE-PORT_OBJS = src/ubus/active-port.o

PROG_CFLAGS = $(CFLAGS) -Wall -Werror
PROG_LDFLAGS = $(LDFLAGS)
PROG_LIBS += -luci -lubus -lubox -lblobmsg_json

INSTALL_DIR = /usr/sbin
	
%.o: %.c
	$(CC) $(PROG_CFLAGS) $(FPIC) -c -o $@ $<

.PHONY: all clean install

all: $(ACTIVE-PORT)
	
$(ACTIVE-PORT): $(ACTIVE-PORT_OBJS)
	$(CC) $(PROG_LDFLAGS) -o $@ $^ $(PROG_LIBS)

clean:
	rm -f $(ACTIVE-PORT)

install: $(ACTIVE-PORT)
	install -m 0755 $(ACTIVE-PORT) $(INSTALL_DIR)
