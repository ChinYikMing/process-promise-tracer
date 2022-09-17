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

### Installing

* clone the repository
* make
* make install

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

## Authors

Contributors names and contact info

ex. 

## Version History

* 0.2
    * Various bug fixes and optimizations
    * See [commit change]() or See [release history]()
* 0.1
    * Initial Release

## License

This project is licensed under the [GPLv3] License - see the LICENSE file for details
