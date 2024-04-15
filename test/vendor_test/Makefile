LIB = libbbfdm_test_ext.so

LIB_OBJS = device.o deviceinfo.o extension.o firewall.o x_test_com_dropbear.o
LIB_CFLAGS = $(CFLAGS) -Wall -Werror -fPIC -I /usr/local/include/
LIB_LDFLAGS = $(LDFLAGS) -lbbfdm-api

%.o: %.c
	$(CC) $(LIB_CFLAGS) $(FPIC) -c -o $@ $<

all: $(LIB)

$(LIB): $(LIB_OBJS)
	$(CC) $(LIB_CFLAGS) $(LIB_LDFLAGS) -shared -o $@ $^

install:
	cp -f $(LIB) /usr/share/bbfdm/plugins/
	cp -f *.json /usr/share/bbfdm/plugins

clean:
	rm -fv *.o $(LIB)
