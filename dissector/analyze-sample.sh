#!/bin/bash

PWD=`pwd`
if [ -z $1 ];then
    echo "Invalid parameter"
elif [ ! -d $1 ];then
    echo "Parameter should be a directory"
else
    for elem in `ls $1`;do
        if [ -f "$1/$elem" ]; then
            python /home/sid/android/apkdissector/dissector/main.py -v 5.1.1 -i "$1/$elem" -o /tmp/asd
        fi
    done
fi