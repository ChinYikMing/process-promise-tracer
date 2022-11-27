all:
	g++ -g record_and_write.cpp `pkg-config --cflags --libs opencv4` -o record_and_write
	objcopy --add-section .record_and_write=sample.json --set-section-flags .mydata=readonly record_and_write promise

dump:
	objdump -sj .record_and_write promise

clean:
	rm -f record_and_write promise