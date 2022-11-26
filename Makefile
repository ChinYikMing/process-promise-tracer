CC = gcc
CFLAGS = -O3 -g -Wall `pkg-config --cflags json-c`
CLIBS = `pkg-config --libs json-c` -pthread -lunwind-ptrace -lunwind-generic

all: process-promise-tracerd.c list.c process.c signal.c perf_sampling.c config.c log.c cpu.c net.c callstack.c
	$(CC) $(CFLAGS) $^ -o process-promise-tracerd $(CLIBS)

install:
ifeq (1, $(shell ./perf_event_open_support.sh))
	#process-promise-tracerd installation
	cp process-promise-tracerd /usr/sbin/
	cp process_promise_tracer.conf /etc/process_promise_tracer.conf 
	#systemd installation
	cp process-promise-tracer.service /etc/systemd/system/
	systemctl daemon-reload
	systemctl enable process-promise-tracer.service
	#rsyslogd installation
	cp process-promise-tracerd.log.conf /etc/rsyslog.d/process-promise-tracerd.conf
	touch /var/log/process_promise_tracer.log
	chmod u+w,g+w,o+w /var/log/process_promise_tracer.log
	systemctl restart rsyslog
	#logrotated installation
	cp process-promise-tracerd.logrotate.conf /etc/logrotate.d/process-promise-tracerd
	systemctl restart logrotate
else
	echo "The kernel do not support perf_event_open system call"
endif

uninstall:
	#logrotated uninstallation
	rm /etc/logrotate.d/process-promise-tracerd
	systemctl restart logrotate
	#rsyslogd uninstallation
	rm /etc/rsyslog.d/process-promise-tracerd.conf
	rm /var/log/process_promise_tracer.log
	systemctl restart rsyslog
	#systemd uninstallation
	systemctl stop process-promise-tracerd
	systemctl disable process-promise-tracerd
	rm /etc/systemd/system/process-promise-tracer.service
	systemctl daemon-reload
	#process-promise-tracerd uninstallation
	rm /usr/sbin/process-promise-tracerd
	#rm /etc/process_promise_tracer.conf

clean:
	rm -f process-promise-tracerd
