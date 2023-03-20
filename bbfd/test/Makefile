LIB = libuspd_test.so

LIB_OBJS = libuspd_test.o
LIB_CFLAGS = $(CFLAGS) -Wall -Werror -fPIC
LIB_LDFLAGS = $(LDFLAGS)

%.o: %.c
	$(CC) $(LIB_CFLAGS) -I/usr/local/include/libbbf_api/ -c -o $@ $<

all: $(LIB)

$(LIB): $(LIB_OBJS)
	$(CC) $(LIB_CFLAGS) $(LIB_LDFLAGS) -shared -o $@ $^

clean:
	rm -fv *.o $(LIB)
