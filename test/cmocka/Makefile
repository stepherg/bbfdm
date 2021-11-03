CC = gcc
CFLAGS = -g -Wall -Werror
LDFLAGS = -lcmocka -lbbfdm -lbbf_api -lubus
LDFLAGS_API_TEST = -lcmocka -lbbf_api -lubus
UNIT_TESTS = unit_test_bbfd
FUNCTIONAL_TESTS = functional_test_bbfd
FUNCTIONAL_API_TESTS = functional_api_test_bbfd

VALGRIND = valgrind --leak-check=full --show-reachable=no \
           --show-leak-kinds=all --errors-for-leak-kinds=all \
           --error-exitcode=1 --track-origins=yes

unit_test_bbfd: unit_test_bbfd.o
	$(CC) -o $@ $^ $(LDFLAGS)

functional_test_bbfd: functional_test_bbfd.o
	$(CC) -o $@ $^ $(LDFLAGS)

functional_api_test_bbfd: functional_api_test_bbfd.o
	$(CC) -o $@ $^ $(LDFLAGS_API_TEST)

unit-test: $(UNIT_TESTS)
	$(foreach testprog, $(UNIT_TESTS), sudo $(VALGRIND) ./$(testprog);)

functional-test: $(FUNCTIONAL_TESTS)
	$(foreach testprog, $(FUNCTIONAL_TESTS), sudo $(VALGRIND) ./$(testprog);)

functional-api-test: $(FUNCTIONAL_API_TESTS)
	$(foreach testprog, $(FUNCTIONAL_API_TESTS), sudo $(VALGRIND) ./$(testprog);)

.PHONY: clean
clean:
	rm -fv *.o $(UNIT_TESTS) $(FUNCTIONAL_TESTS) $(FUNCTIONAL_API_TESTS)

