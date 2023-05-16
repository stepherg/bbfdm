LIB_WIFI_DATAELEMENTS = libwifi_dataelements.so

LIB_WIFI_DATAELEMENTS_OBJS = wifi_dataelements.o ../../libbbfdm/dmtree/tr181/wifi.dataelements.o
LIB_CFLAGS = $(CFLAGS) -Wall -Werror -fPIC -I /usr/local/include/
LIB_LDFLAGS = $(LDFLAGS) -lbbfdm-api

%.o: %.c
	$(CC) $(LIB_CFLAGS) $(FPIC) -c -o $@ $<

all: $(LIB_WIFI_DATAELEMENTS)

$(LIB_WIFI_DATAELEMENTS): $(LIB_WIFI_DATAELEMENTS_OBJS)
	$(CC) $(LIB_CFLAGS) $(LIB_LDFLAGS) -shared -o $@ $^

clean:
	rm -fv *.o $(LIB_WIFI_DATAELEMENTS)
