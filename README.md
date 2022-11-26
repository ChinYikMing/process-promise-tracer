# Process Promise Tracer

Software processes have to list out the promises of accessing peripheral devices such as webcam clearly, so our program can check the actions of the
software processes periodically to ensure that they do not violate the promise.

## Description

Nowadays, any kind of software processes require accessing the peripheral devices to achieve some functionality such as video chatting application.
Let us take the video chatting application for continuous explanation. Normally, the application will ask the user to handout control of the webcam
before using it, but it does not tell the user what is it going to further do with the data from the webcam behind the scene, so it could be kind of
insecure issues about the behind scene actions for example record down the video secretly.

## Getting Started

### Dependencies

* Ubuntu 20.04
* gcc
* make
* libelf-dev
* [json-c](https://github.com/json-c/json-c)
* [libunwind](https://github.com/libunwind/libunwind)

### Installing

* clone the repository or via release(assets need to be decompressed)
* make
* make install

### Uninstalling

* make uninstall

### Executing program

* the program is a daemon, you can control it via systemctl command

* start the daemon
```
$systemctl start process-promise-tracerd
```

* stop the daemon
```
$systemctl stop process-promise-tracerd
```

* restart the daemon
```
$systemctl restart process-promise-tracerd
```

* reload the daemon config
```
$systemctl reload process-promise-tracerd
```

* check the status of the daemon
```
$systemctl status process-promise-tracerd
```

* enable the daemon automatically startup after booting
```
$systemctl enable process-promise-tracerd
```

### Program Configuration file
* located in /etc/process_promise_tracer.conf
* There are two sections in the config file: [Daemon] and [Untrusted Program]
* [Daemon] is for daemon config and [Untrusted Program] is for untrusted program name to be traced
* Sample configuration file, only /usr/bin/test program will be traced by the daemon program
```
[Daemon]
perf_sample_period=3000
scan_procfs_period=1000

[Untrusted Program]
/usr/bin/test
```

## Version History

* 1.0
    * [Initial Release](https://github.com/ChinYikMing/process-promise-tracer/releases/tag/v1.0)

## License

This project is licensed under the [GPLv3] License - see the LICENSE file for details
