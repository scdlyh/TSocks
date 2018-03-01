#!/system/bin/sh

#当前执行目录路径
DIR="`pwd`"||DIR="`/system/bin/busybox pwd`"||DIR="`/system/bin/toybox pwd`"||DIR="${0%/*}" > /dev/null 2>&1||exit $?

/system/bin/sh ${DIR}/TSocks -x ${DIR}
