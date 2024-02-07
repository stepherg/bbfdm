CC = gcc
CFLAGS = -g -Wall -Werror
LDFLAGS = -lcmocka -lbbfdm-api -lbbfdm
UNIT_TESTS = bbfdm_unit_test

VALGRIND = valgrind --leak-check=full --show-reachable=no \
           --show-leak-kinds=all --errors-for-leak-kinds=all \
           --error-exitcode=1 --track-origins=yes

bbfdm_unit_test: bbfdm_unit_test.o
	$(CC) -o $@ $^ $(LDFLAGS)

unit-test: $(UNIT_TESTS)
	$(foreach testprog, $(UNIT_TESTS), sudo $(VALGRIND) ./$(testprog);)

.PHONY: clean
clean:
	rm -fv *.o $(UNIT_TESTS)
