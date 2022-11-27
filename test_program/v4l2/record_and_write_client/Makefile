all:
	g++ -g record_and_write_client.cpp `pkg-config --cflags --libs opencv4` -o record_and_write_client
	objcopy --add-section .record_and_write_client=sample.json --set-section-flags .mydata=readonly record_and_write_client promise

dump:
	objdump -sj .record_and_write_client promise

clean:
	rm -f record_and_write_client promise