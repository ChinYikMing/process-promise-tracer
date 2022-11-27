all:
	g++ -g record_and_write_client.cpp `pkg-config --cflags --libs opencv4` -o record_and_write_client
	objcopy --add-section .test=sample.json --set-section-flags .mydata=readonly record_and_write_client promise
	g++ -g record_and_write_client8081.cpp `pkg-config --cflags --libs opencv4` -o record_and_write_client8081
	objcopy --add-section .test=sample.json --set-section-flags .mydata=readonly record_and_write_client8081 promise8081

dump:
	objdump -sj .test promise

clean:
	rm -f record_and_write_client8081 record_and_write_client promise promise8081
