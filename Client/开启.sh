#!/system/bin/sh

#系统命令默认路径
BIN="/system/bin"
#当前执行目录路径
DIR="`pwd`"||DIR="`$BIN/busybox pwd`"||DIR="`$BIN/toybox pwd`"||DIR="${0%/*}" > /dev/null 2>&1||exit $?

${BIN}/sh ${DIR}/TSocks -s ${BIN} ${DIR}
