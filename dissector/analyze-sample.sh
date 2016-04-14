#!/bin/bash

PWD=`pwd`
if [ -z $1 ];then
    echo "Invalid parameter"
elif [ ! -d $1 ];then
    echo "Parameter should be a directory"
else
    i=0
    for elem in `ls $1`;do
        if [ -f "$1$elem" ]; then
            if [ $i -lt 5 ]; then
                echo "Launching thread $i"
                python /home/sid/android/apkdissector/dissector/main.py -v 5.1.1 -i "$1$elem" -o /tmp/clean-sd1 &
                i=$(($i + 1))
            else
                #Waiting for the threads launched
                wait
                i=0
                #Launch the element we have when i = 5
                echo "Launching thread $i"
                python /home/sid/android/apkdissector/dissector/main.py -v 5.1.1 -i "$1$elem" -o /tmp/clean-sd1 &
                i=$(($i + 1))
            fi
        fi
    done
fi