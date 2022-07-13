BIN = bbf_ubus

BIN_OBJ = bbf_ubus.o
BIN_CFLAGS = $(CFLAGS) -Wall -Werror -fPIC -I /usr/local/include/
BIN_LDFLAGS = $(LDFLAGS) -lbbf_ubus -lubus -lubox -lbbf_test

%.o: %.c
	$(CC) $(BIN_CFLAGS) $(FPIC) -c -o $@ $<

all: $(BIN)

$(BIN): $(BIN_OBJ)
	$(CC) -o $@ $^ $(BIN_LDFLAGS)

clean:
	rm -fv *.o $(BIN)
