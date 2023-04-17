LIB = libbbf_test.so
BIN = bbf_dm

BIN_OBJ = bbf_dm.o
LIB_OBJS = libbbf_test.o
LIB_CFLAGS = $(CFLAGS) -Wall -Werror -fPIC -I /usr/local/include/
LIB_LDFLAGS = $(LDFLAGS) -lbbfdm-api
BIN_LDFLAGS = $(LDFLAGS) -lbbfdm-api -lbbfdm

%.o: %.c
	$(CC) $(LIB_CFLAGS) $(FPIC) -c -o $@ $<

all: $(LIB) $(BIN)

$(LIB): $(LIB_OBJS)
	$(CC) $(LIB_CFLAGS) $(LIB_LDFLAGS) -shared -o $@ $^

$(BIN): $(BIN_OBJ)
	$(CC) -o $@ $^ $(BIN_LDFLAGS)

clean:
	rm -fv *.o $(LIB) $(BIN)
