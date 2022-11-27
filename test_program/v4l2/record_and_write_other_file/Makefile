all:
	g++ -g record_and_write_other_file_late.cpp `pkg-config --cflags --libs opencv4` -o record_and_write_other_file_late
	objcopy --add-section .test=sample.json --set-section-flags .mydata=readonly record_and_write_other_file_late promise

dump:
	objdump -sj .test promise

clean:
	rm -f record_and_write_other_file_late promise
