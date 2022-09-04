all:
	gcc -g `pkg-config --cflags json-glib-1.0` process-promise-tracerd.c list.c process.c signal.c config.c -o process-promise-tracerd `pkg-config --libs json-glib-1.0`

clean:
	rm -f process-promise-tracerd