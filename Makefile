all:
	gcc -g `pkg-config --cflags json-glib-1.0` process-promise-tracerd.c list.c process.c signal.c config.c -o process-promise-tracerd `pkg-config --libs json-glib-1.0`

install:
	cp process-promise-tracerd /usr/sbin/
	touch /etc/process_promise_tracer.conf
	cp process-promise-tracer.service /etc/systemd/system/
	systemctl daemon-reload
	systemctl enable process-promise-tracer.service

uninstall:
	systemctl stop process-promise-tracerd
	systemctl disable process-promise-tracerd
	rm /etc/systemd/system/process-promise-tracer.service
	systemctl daemon-reload
	rm /usr/sbin/process-promise-tracerd

clean:
	rm -f process-promise-tracerd
