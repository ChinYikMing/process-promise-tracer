all:
	g++ -g record.cpp `pkg-config --cflags --libs opencv4` -o record
	objcopy --add-section .test=sample.json --set-section-flags .mydata=readonly record promise

dump:
	objdump -sj .test promise

clean:
	rm -f record promise
