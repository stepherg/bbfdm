LIB = libbbf_test.so

LIB_OBJS = libbbf_test.o
LIB_CFLAGS = $(CFLAGS) -Wall -Werror -fPIC
LIB_LDFLAGS = $(LDFLAGS) -lbbf_api

%.o: %.c
	$(CC) $(PROG_CFLAGS) $(FPIC) -c -o $@ $<

all: $(LIB)

$(LIB): $(LIB_OBJS)
	$(CC) $(LIB_CFLAGS) $(LIB_LDFLAGS) -shared -o $@ $^

clean:
	rm -fv *.o $(LIB)
