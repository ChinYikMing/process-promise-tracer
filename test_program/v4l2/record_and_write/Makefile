all:
	g++ -g record_and_write.cpp `pkg-config --cflags --libs opencv4` -o record_and_write
	objcopy --add-section .test=sample.json --set-section-flags .mydata=readonly record_and_write promise

dump:
	objdump -sj .test promise

clean:
	rm -f record_and_write promise
