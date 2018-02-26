#!/system/bin/sh

#当前执行目录路径
DIR="`pwd`"||DIR="`$BIN/busybox pwd`"||DIR="`$BIN/toybox pwd`"||DIR="${0%/*}" > /dev/null 2>&1||exit $?

${BIN}/sh ${DIR}/TSocks -x ${DIR}
