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
* libjson-glib-1.0-0
* libjson-glib-1.0-common
* libjson-glib-dev

### Installing

* clone the repository
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

### Program Configuration file
* located in /etc/process_promise_tracer.conf
* Each line is a program name to be traced
* Sample configuration file, only /usr/bin/test program will be traced by the daemon program
```
/usr/bin/test
```

## Bugs

1. ptrace attached process cannot terminated using control-C
2. ptrace will block the daemon process to trace other processes until the ptrace attached process finishes execution

## Bugs Reduplication

make install 之後修改 /etc/process_promise_tracer.conf 增加 test/camera_test/example/example 的執行路徑， 一個 terminal 執行 ./process-promise-tracerd, 一個 terminal 執行 test/camera_test/example/example，
會發現無法用 control-C 結束 test/camera_test/example/example, ./process-promise-tracerd 則會被 blocked 直到 test/camera_test/example/example 執行結束

## Version History

* 0.2
    * Various bug fixes and optimizations
    * See [commit change]() or See [release history]()
* 0.1
    * Initial Release

## License

This project is licensed under the [GPLv3] License - see the LICENSE file for details
