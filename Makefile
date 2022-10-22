CC = gcc
CFLAGS = -g -Wall `pkg-config --cflags json-glib-1.0`
CLIBS = `pkg-config --libs json-glib-1.0`

all: process-promise-tracerd.c list.c process.c signal.c perf_va.c config.c syscall_trace.c cache_va.c
	$(CC) $(CFLAGS) $^ -o process-promise-tracerd $(CLIBS)

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
