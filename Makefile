all:
	gcc -g process-promise-tracerd.c list.c process.c signal.c config.c -o process-promise-tracerd

clean:
	rm -f process-promise-tracerd
