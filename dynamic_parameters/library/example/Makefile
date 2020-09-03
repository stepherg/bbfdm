LIB_EXAMPLE := libexample.so

OBJS  := example.o

LIB_CFLAGS = $(CFLAGS) -fstrict-aliasing
LIB_LDFLAGS = $(LDFLAGS) -lbbf_api
FPIC := -fPIC

.PHONY: all

%.o: %.c
	$(CC) $(LIB_CFLAGS) $(FPIC) -c -o $@ $<

all: $(LIB_EXAMPLE)

$(LIB_EXAMPLE): $(OBJS)
	$(CC) $(LIB_CFLAGS) $(LIB_LDFLAGS) -shared -o $@ $^

clean:
	rm -f *.o $(LIB_EXAMPLE)

