all:
	g++ -g record_and_write_other_file_late.cpp `pkg-config --cflags --libs opencv4` -o record_and_write_other_file_late
	objcopy --add-section .record_and_write_other_file_late=sample.json --set-section-flags .mydata=readonly record_and_write_other_file_late promise

dump:
	objdump -sj .record_and_write_other_file_late promise

clean:
	rm -f record_and_write_other_file_late promise