PROG = uspd
OBJS =common.o get.o get_helper.o set.o operate.o add_delete.o pretty_print.o usp.o events.o
CP=cp -f

PROG_CFLAGS = $(CFLAGS) \
	      -fstrict-aliasing \
	      -Wall -Wextra -Werror \
	      -Wformat \
	      -Wformat-signedness -fPIC

PROG_LDFLAGS = $(LDFLAGS)
PROG_LDFLAGS += -luci -lubus -lubox -ljson-c -lblobmsg_json -lbbfdm

ifeq ($(USE_MBEDTLS),yes)
PROG_LDFLAGS += -lmbedcrypto -lmbedtls
endif

ifeq ($(USE_OPENSSL),yes)
PROG_LDFLAGS += -lssl -lcrypto
endif

ifeq ($(USE_WOLFSSL),yes)
PROG_LDFLAGS += -lwolfssl
endif

%.o: %.c
	$(CC) $(PROG_CFLAGS) -c -o $@ $<

all: ${PROG}

${PROG}: $(OBJS)
	$(CC) $(PROG_CFLAGS) -o $@ $^ $(PROG_LDFLAGS)
	$(CP) ${PROG} ../${PROG}

test: PROG_CFLAGS += -fPIC
test: ${OBJS}
	${CC} $(PROG_CFLAGS) -shared -o libuspd.so ${OBJS} $(PROG_LDFLAGS)
	$(CP) libuspd.so ../libuspd.so

unit-test: CFLAGS  += -g -O0 -fprofile-arcs -ftest-coverage
unit-test: LDFLAGS += --coverage
unit-test: clean_objs
unit-test: test
	make -C ../test/cmocka unit-test USPD_LIB_DIR=$(PWD)

func-test: CFLAGS  += -g -O0 -fprofile-arcs -ftest-coverage
func-test: LDFLAGS += --coverage
func-test: clean_objs
func-test: ${PROG}

clean_objs:
	rm -f *.o
clean:
	rm -f *.o libuspd.so $(PROG)
	rm -f *.xml *.html
	find -name '*.gcda' -exec rm {} -fv \;
	find -name '*.gcno' -exec rm {} -fv \;
	find -name '*.gcov' -exec rm {} -fv \;
