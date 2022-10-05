all:
	gcc -g test.c -o test
	objcopy --add-section .test=sample.json --set-section-flags .mydata=readonly test promise_test

dump:
	objdump -sj .test promise_test

clean:
	rm -f test promise_test
