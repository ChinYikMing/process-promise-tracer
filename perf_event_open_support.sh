#!/bin/bash

file=/proc/sys/kernel/perf_event_paranoid
if [ -f "$file" ];
then
	echo 1
else
	echo 0
fi
