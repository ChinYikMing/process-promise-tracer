all:
	g++ -g server8080.cpp -o server8080 `pkg-config --cflags --libs opencv4`
	g++ -g server8081.cpp -o server8081 `pkg-config --cflags --libs opencv4`

clean:
	rm -f server8080 server8081
