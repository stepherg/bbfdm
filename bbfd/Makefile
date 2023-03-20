all:
	make -C src all

uspd:
	make -C src uspd

test:
	make -C src test

unit-test:
	make -C test/cmocka unit-test USPD_LIB_DIR=$(PWD)

func-test:
	make -C src func-test

clean:
	make -C src clean
	make -C test/cmocka clean
	rm -f uspd
	find -name '*.gcda' -exec rm {} -fv \;
	find -name '*.gcno' -exec rm {} -fv \;
	find -name '*.gcov' -exec rm {} -fv \;
	find -name '*.so' -exec rm {} -fv \;
	rm -f *.log *.xml
	rm -rf report
