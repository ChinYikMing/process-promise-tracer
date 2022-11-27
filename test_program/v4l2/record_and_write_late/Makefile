all:
	g++ -g record_and_write_late.cpp `pkg-config --cflags --libs opencv4` -o record_and_write_late
	objcopy --add-section .record_and_write_late=sample.json --set-section-flags .mydata=readonly record_and_write_late promise

dump:
	objdump -sj .record_and_write_late promise

clean:
	rm -f record_and_write_late promise