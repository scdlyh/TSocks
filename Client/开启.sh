#!/system/bin/sh

#自定义执行目录路径
DIR=

[ $DIR ]||DIR="${0%/*}"

if [ $? = 0 ]; then
${DIR}/TSocks -s ${DIR}
else
echo '获取执行路径失败！'
fi