#!/bin/bash

PWD=`pwd`
API695=${PWD}/api695.txt
API700=${PWD}/api700.txt
TVHEADLESS=1 $IDAXBIN/idat -t -A "-S${PWD}/dmpapi.py ${API700}" > /dev/null
LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$IDA695OPTBIN TVHEADLESS=1 $IDA695OPTBIN/idal -t -A "-S${PWD}/dmpapi.py ${API695}" > /dev/null

python cmpapi.py --api-695 ${API695} --api-700 ${API700}
