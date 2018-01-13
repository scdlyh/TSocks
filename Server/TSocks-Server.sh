#!/usr/bin/env bash
#
# Auto install TSocks Server
#
# Copyright (C) 2017-2018 强插GFW <yiguihai@gmail.com>
#
# System Required:  CentOS 6+, Debian7+, Ubuntu12+
#
# Reference URL:
# https://github.com/shadowsocks/shadowsocks-libev
# https://github.com/shadowsocks/shadowsocks-android
#
# Thanks:
# @clowwindy  <https://twitter.com/clowwindy>
# @cyfdecyf   <https://twitter.com/cyfdecyf>
# @madeye     <https://github.com/madeye>
# 
# Intro:  https://teddysun.com/486.html

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

[[ $EUID -ne 0 ]] && echo -e "[${red}错误提示${plain}] This script must be run as root!" && exit 1

DIR=$( pwd )
software=(Shadowsocks-libev Gost)

libsodium_file="libsodium-1.0.16"
libsodium_url="https://github.com/jedisct1/libsodium/releases/download/1.0.16/libsodium-1.0.16.tar.gz"

mbedtls_file="mbedtls-2.6.0"
mbedtls_url="https://tls.mbed.org/download/mbedtls-2.6.0-gpl.tgz"

shadowsocks_libev_init="/etc/init.d/shadowsocks-libev"
shadowsocks_libev_config="/etc/shadowsocks-libev/config.json"
shadowsocks_libev_centos="https://raw.githubusercontent.com/yiguihai/TSocks/master/Server/shadowsocks-libev.sh"
shadowsocks_libev_debian="https://raw.githubusercontent.com/yiguihai/TSocks/master/Server/shadowsocks-libev-debian.sh"

gost_init="/etc/init.d/gost"
gost_config="/usr/local/bin/gost.json"
gost_centos="https://raw.githubusercontent.com/yiguihai/TSocks/master/Server/gost.sh"
gost_debian="https://raw.githubusercontent.com/yiguihai/TSocks/master/Server/gost-debian.sh"

print_info(){
    clear
    echo
echo "#############################################################"
echo "# One click Install Shadowsocks+gost Server                 #"
echo "# Intro: https://qxgfw.wodemo.com                           #"
echo "# Github: https://github.com/yiguihai/TSocks                #"
echo "#############################################################"
echo
}

# Stream Ciphers
common_ciphers=(
aes-256-gcm
aes-192-gcm
aes-128-gcm
aes-256-ctr
aes-192-ctr
aes-128-ctr
aes-256-cfb
aes-192-cfb
aes-128-cfb
camellia-128-cfb
camellia-192-cfb
camellia-256-cfb
xchacha20-ietf-poly1305
chacha20-ietf-poly1305
chacha20-ietf
chacha20
salsa20
rc4-md5
)

# libev obfuscating
obfs_libev=(http tls)
# initialization parameter
libev_obfs=""

disable_selinux() {
   if [ -s /etc/selinux/config ] && grep 'SELINUX=enforcing' /etc/selinux/config; then
        sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
        setenforce 0
    fi
}

check_sys() {
    local checkType=$1
    local value=$2

    local release=''
    local systemPackage=''

    if [ -f /etc/redhat-release ]; then
        release="centos"
        systemPackage="yum"
    elif cat /etc/issue | grep -Eqi "debian"; then
        release="debian"
        systemPackage="apt"
    elif cat /etc/issue | grep -Eqi "ubuntu"; then
        release="ubuntu"
        systemPackage="apt"
    elif cat /etc/issue | grep -Eqi "centos|red hat|redhat"; then
        release="centos"
        systemPackage="yum"
    elif cat /proc/version | grep -Eqi "debian"; then
        release="debian"
        systemPackage="apt"
    elif cat /proc/version | grep -Eqi "ubuntu"; then
        release="ubuntu"
        systemPackage="apt"
    elif cat /proc/version | grep -Eqi "centos|red hat|redhat"; then
        release="centos"
        systemPackage="yum"
    fi

    if [ ${checkType} == "sysRelease" ]; then
        if [ "$value" == "$release" ]; then
            return 0
        else
            return 1
        fi
    elif [ ${checkType} == "packageManager" ]; then
        if [ "$value" == "$systemPackage" ]; then
            return 0
        else
            return 1
        fi
    fi
}

version_ge(){
    test "$(echo "$@" | tr " " "\n" | sort -rV | head -n 1)" == "$1"
}

version_gt(){
    test "$(echo "$@" | tr " " "\n" | sort -V | head -n 1)" != "$1"
}

check_kernel_version() {
    local kernel_version=$(uname -r | cut -d- -f1)
    if version_gt ${kernel_version} 3.7.0; then
        return 0
    else
        return 1
    fi
}

getversion() {
    if [[ -s /etc/redhat-release ]]; then
        grep -oE  "[0-9.]+" /etc/redhat-release
    else
        grep -oE  "[0-9.]+" /etc/issue
    fi
}

centosversion() {
    if check_sys sysRelease centos; then
        local code=$1
        local version="$(getversion)"
        local main_ver=${version%%.*}
        if [ "$main_ver" == "$code" ]; then
            return 0
        else
            return 1
        fi
    else
        return 1
    fi
}

autoconf_version(){
    if [ ! "$(command -v autoconf)" ]; then
        echo -e "[${green}提示信息${plain}] 开始安装 autoconf..."
        if check_sys packageManager yum; then
            yum install -y autoconf > /dev/null 2>&1
        elif check_sys packageManager apt; then
            apt-get -y update > /dev/null 2>&1
            apt-get -y install autoconf > /dev/null 2>&1
        fi
        echo -e "[${green}提示信息${plain}] 安装 autoconf 完成."
    fi
    local autoconf_ver=$(autoconf --version | grep autoconf | grep -oE "[0-9.]+")
    if version_ge ${autoconf_ver} 2.67; then
        return 0
    else
        return 1
    fi
}

get_ip() {
    local IP=$( ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )
    [ -z ${IP} ] && IP=$( wget -qO- -t1 -T2 ipv4.icanhazip.com )
    [ -z ${IP} ] && IP=$( wget -qO- -t1 -T2 ipinfo.io/ip )
    [ ! -z ${IP} ] && echo ${IP} || echo
}

get_ipv6(){
    local ipv6=$(wget -qO- -t1 -T2 ipv6.icanhazip.com)
    [ -z ${ipv6} ] && return 1 || return 0
}

get_libev_ver(){
    libev_ver=$(wget --no-check-certificate -qO- https://api.github.com/repos/shadowsocks/shadowsocks-libev/releases/latest | grep 'tag_name' | cut -d\" -f4)
    [ -z ${libev_ver} ] && echo -e "[${red}错误提示${plain}] 获取 shadowsocks-libev 最新版失败!" && exit 1
}

get_gost_ver(){
    gost_ver=$(wget --no-check-certificate -qO- https://api.github.com/repos/ginuerzh/gost/releases/latest | grep 'tag_name' | cut -d\" -f4)
    [ -z ${gost_ver} ] && echo -e "[${red}错误提示${plain}] 获取 gost 最新版失败!" && exit 1
}

get_opsy(){
    [ -f /etc/redhat-release ] && awk '{print ($1,$3~/^[0-9]/?$3:$4)}' /etc/redhat-release && return
    [ -f /etc/os-release ] && awk -F'[= "]' '/PRETTY_NAME/{print $3,$4,$5}' /etc/os-release && return
    [ -f /etc/lsb-release ] && awk -F'[="]+' '/DESCRIPTION/{print $2}' /etc/lsb-release && return
}

is_64bit() {
    if [ `getconf WORD_BIT` = '32' ] && [ `getconf LONG_BIT` = '64' ] ; then
        return 0
    else
        return 1
    fi
}

debianversion(){
    if check_sys sysRelease debian;then
        local version=$( get_opsy )
        local code=${1}
        local main_ver=$( echo ${version} | sed 's/[^0-9]//g')
        if [ "${main_ver}" == "${code}" ];then
            return 0
        else
            return 1
        fi
    else
        return 1
    fi
}

download() {
    local filename=$(basename $1)
    if [ -f ${1} ]; then
        echo "${filename} [发现已存在]"
    else
        echo "${filename} 文件未找到, 下载开始..."
        wget --no-check-certificate -c -t3 -T60 -O ${1} ${2}
        if [ $? -ne 0 ]; then
            echo -e "[${red}错误提示${plain}] 下载 ${filename} 失败!"
            exit 1
        fi
    fi
}

download_files() {
    cd ${DIR}

    if   [ "${selected}" == "1" ]; then
        get_libev_ver
        shadowsocks_libev_file="shadowsocks-libev-$(echo ${libev_ver} | sed -e 's/^[a-zA-Z]//g')"
        shadowsocks_libev_url="https://github.com/shadowsocks/shadowsocks-libev/releases/download/${libev_ver}/${shadowsocks_libev_file}.tar.gz"

        if check_sys packageManager yum; then
            download "${shadowsocks_libev_init}" "${shadowsocks_libev_centos}"
        elif check_sys packageManager apt; then
            download "${shadowsocks_libev_init}" "${shadowsocks_libev_debian}"
        fi
        download "${shadowsocks_libev_file}.tar.gz" "${shadowsocks_libev_url}"
    elif [ "${selected}" == "2" ]; then
        get_gost_ver
        if is_64bit; then
        gost_file="gost_$(echo ${gost_ver} | sed -e 's/^[a-zA-Z]//g')_linux_amd64"
        else
        gost_file="gost_$(echo ${gost_ver} | sed -e 's/^[a-zA-Z]//g')_linux_386"
        fi
        gost_url="https://github.com/ginuerzh/gost/releases/download/${gost_ver}/${gost_file}.tar.gz"
        if check_sys packageManager yum; then
            download "${gost_init}" "${gost_centos}"
        elif check_sys packageManager apt; then
            download "${gost_init}" "${gost_debian}"
        fi
        download "${gost_file}.tar.gz" "${gost_url}"
    fi

}

boot_init() {
    local service_name=$(basename ${1})
if   [ "${2}" == "on" ]; then
    chmod +x ${1}
    if check_sys packageManager yum; then
            chkconfig --add ${service_name}
            chkconfig ${service_name} on
        elif check_sys packageManager apt; then
            update-rc.d -f ${service_name} defaults
     fi
elif [ "${2}" == "off" ]; then
    ${1} stop
    if check_sys packageManager yum; then
        chkconfig --del ${service_name}
    elif check_sys packageManager apt; then
        update-rc.d -f gost remove
    fi

fi
}

get_char() {
    SAVEDSTTY=`stty -g`
    stty -echo
    stty cbreak
    dd if=/dev/tty bs=1 count=1 2> /dev/null
    stty -raw
    stty echo
    stty $SAVEDSTTY
}

error_detect_depends(){
    local command=$1
    local depend=`echo "${command}" | awk '{print $4}'`
    ${command}
    if [ $? != 0 ]; then
        echo -e "[${red}错误提示${plain}] 没有安装 ${red}${depend}${plain}"
        echo "请访问: https://teddysun.com/486.html 获取帮助."
        exit 1
    fi
}

config_firewall() {
    if centosversion 6; then
        /etc/init.d/iptables status > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            iptables -L -n | grep -i ${1} > /dev/null 2>&1
            if [ $? -ne 0 ]; then
                iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${1} -j ACCEPT
                iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${1} -j ACCEPT
                /etc/init.d/iptables save
                /etc/init.d/iptables restart
            else
                echo -e "[${green}提示信息${plain}] 防火墙已经开放 ${green}${1}${plain} 端口"
            fi
        else
            echo -e "[${yellow}警告信息${plain}] iptables 看起来没有运行或者没有安装, 如有必要请手动打开 ${1} 端口."
        fi
    elif centosversion 7; then
        systemctl status firewalld > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            firewall-cmd --permanent --zone=public --add-port=${1}/tcp
            firewall-cmd --permanent --zone=public --add-port=${1}/udp
            firewall-cmd --reload
        else
            echo -e "[${yellow}警告信息${plain}] 看起来没有运行或者没有安装, 如有必要请手动打开 ${1} 端口."
        fi
    fi
}

config_shadowsocks() {

    if check_kernel_version; then
    fast_open="true"
    else
    fast_open="false"
    fi

    local server_value="\"0.0.0.0\""
    if get_ipv6; then
        server_value="[\"[::0]\",\"0.0.0.0\"]"
    fi

    if [ ! -d "$(dirname ${shadowsocks_libev_config})" ]; then
        mkdir -p $(dirname ${shadowsocks_libev_config})
    fi
    if [ "${libev_obfs}" == "y" ] || [ "${libev_obfs}" == "Y" ]; then
        cat > ${shadowsocks_libev_config}<<-EOF
{
    "server":${server_value},
    "server_port":${shadowsocksport},
    "local_address":"127.0.0.1",
    "local_port":1080,
    "password":"${shadowsockspwd}",
    "timeout":300,
    "method":"${shadowsockscipher}",
    "fast_open":${fast_open},
    "plugin":"obfs-server --obfs ${shadowsocklibev_obfs}"
}
EOF
    else
        cat > ${shadowsocks_libev_config}<<-EOF
{
    "server":${server_value},
    "server_port":${shadowsocksport},
    "local_address":"127.0.0.1",
    "local_port":1080,
    "password":"${shadowsockspwd}",
    "timeout":300,
    "method":"${shadowsockscipher}",
    "fast_open":${fast_open}
}
EOF
    fi
}

config_gost() {
if [ ! -d "$(dirname ${gost_config})" ]; then
    mkdir -p $(dirname ${gost_config})
fi
    cat > ${gost_config}<<-EOF
{
    "ServeNodes": [
        "socks5://${gostuser}:${gostpwd}@${gostaddress}:${gostport}"
    ]
}
EOF
}

install_dependencies() {
    if check_sys packageManager yum; then
        echo -e "[${green}提示信息${plain}] 检查 EPEL repository..."
        if [ ! -f /etc/yum.repos.d/epel.repo ]; then
            yum install -y -q epel-release
        fi
        [ ! -f /etc/yum.repos.d/epel.repo ] && echo -e "[${red}错误提示${plain}] 安装 EPEL repository 失败, 请检查后重试." && exit 1
        [ ! "$(command -v yum-config-manager)" ] && yum install -y -q yum-utils
        if [ x"`yum-config-manager epel | grep -w enabled | awk '{print $3}'`" != x"True" ]; then
            yum-config-manager --enable epel
        fi
        echo -e "[${green}提示信息${plain}] 检查 EPEL repository 完整性..."

        yum_depends=(
            unzip gzip openssl openssl-devel gcc pcre pcre-devel libtool libevent xmlto
            autoconf automake make curl curl-devel zlib-devel perl perl-devel cpio expat-devel gettext-devel asciidoc
            libev-devel c-ares-devel git qrencode
        )
        for depend in ${yum_depends[@]}; do
            error_detect_depends "yum -y install ${depend} -q"
        done
    elif check_sys packageManager apt; then
        apt_depends=(
            gettext build-essential unzip gzip curl openssl libssl-dev
            autoconf automake libtool gcc make perl cpio libpcre3 libpcre3-dev zlib1g-dev libev-dev libc-ares-dev git qrencode
        )
        apt-get -y update
        for depend in ${apt_depends[@]}; do
            error_detect_depends "apt-get -y install ${depend}"
        done
    fi
}

install_check() {
    if check_sys packageManager yum || check_sys packageManager apt; then
        if centosversion 5; then
            return 1
        fi
        return 0
    else
        return 1
    fi
}

install_select() {
    if ! install_check; then
        echo -e "[${red}错误提示${plain}] 您的操作系统不支持运行这个脚本!"
        echo "请更换为 CentOS 6+/Debian 7+/Ubuntu 12+ 然后再试一次."
        exit 1
    fi
    clear
    print_info
    while true
    do
    echo  "请选择你需要安装的代理服务:"
    for ((i=1;i<=${#software[@]};i++ )); do
        hint="${software[$i-1]}"
        echo -e "${green}${i}${plain}) ${hint}"
    done
    read -p "请输入一个数字进行选择 (默认 ${software[0]}):" selected
    [ -z "${selected}" ] && selected="1"
    case "${selected}" in
        1|2)
        echo
        echo "你的选择 = ${software[${selected}-1]}"
        echo
        break
        ;;
        *)
        echo -e "[${red}错误提示${plain}] Please only enter a number [1-2]"
        ;;
    esac
    done
    install_main
}

install_prepare_password() {
    echo "请设置一个密码 ${software[${selected}-1]}"
    read -p "(默认密码: teddysun.com):" shadowsockspwd
    [ -z "${shadowsockspwd}" ] && shadowsockspwd="teddysun.com"
    echo
    echo "你输入的密码 = ${shadowsockspwd}"
    echo
}

install_prepare_port() {
    while true
    do
    echo -e "请设置一个端口 ${software[${selected}-1]} [1-65535]"
    read -p "(默认端口: 8989):" shadowsocksport
    [ -z "${shadowsocksport}" ] && shadowsocksport="8989"
    expr ${shadowsocksport} + 1 &>/dev/null
    if [ $? -eq 0 ]; then
        if [ ${shadowsocksport} -ge 1 ] && [ ${shadowsocksport} -le 65535 ] && [ ${shadowsocksport:0:1} != 0 ]; then
            echo
            echo "你输入的端口 = ${shadowsocksport}"
            echo
            break
        fi
    fi
    echo -e "[${red}错误提示${plain}] 请输入一个正确的数字 [1-65535]"
    done
}

install_prepare_cipher() {
    while true
    do
    echo -e "请选择设置一个加密方法 ${software[${selected}-1]}:"

    if   [[ "${selected}" == "1" ]]; then
        for ((i=1;i<=${#common_ciphers[@]};i++ )); do
            hint="${common_ciphers[$i-1]}"
            echo -e "${green}${i}${plain}) ${hint}"
        done
        read -p "你要选择那一个加密方法? (默认: ${common_ciphers[0]}):" pick
        [ -z "$pick" ] && pick=1
        expr ${pick} + 1 &>/dev/null
        if [ $? -ne 0 ]; then
            echo -e "[${red}错误提示${plain}] 请输入一个数字进行选择"
            continue
        fi
        if [[ "$pick" -lt 1 || "$pick" -gt ${#common_ciphers[@]} ]]; then
            echo -e "[${red}错误提示${plain}] 请输入一个数字进行选择 1 -${#common_ciphers[@]}之间"
            continue
        fi
        shadowsockscipher=${common_ciphers[$pick-1]}
    fi

    echo
    echo "你选择的加密方法 = ${shadowsockscipher}"
    echo
    break
    done
}

install_prepare_libev_obfs() {
    if autoconf_version; then
        while true
        do
        echo -e "请问您是否需要安装 simple-obfs 流量混淆插件 ?  ${software[${selected}-1]} [y/n]"
        read -p "(默认: n):" libev_obfs
        [ -z "$libev_obfs" ] && libev_obfs=n
        case "${libev_obfs}" in
            y|Y|n|N)
            echo
            echo "您的选择 = ${libev_obfs}"
            echo
            break
            ;;
            *)
            echo -e "[${red}错误提示${plain}] Please only enter [y/n]"
            ;;
        esac
        done

        if [ "${libev_obfs}" == "y" ] || [ "${libev_obfs}" == "Y" ]; then
            while true
            do
            echo -e "请选择一个流量混淆方式:"
            for ((i=1;i<=${#obfs_libev[@]};i++ )); do
                hint="${obfs_libev[$i-1]}"
                echo -e "${green}${i}${plain}) ${hint}"
            done
            read -p "Which obfs you'd select(默认: ${obfs_libev[0]}):" r_libev_obfs
            [ -z "$r_libev_obfs" ] && r_libev_obfs=1
            expr ${r_libev_obfs} + 1 &>/dev/null
            if [ $? -ne 0 ]; then
                echo -e "[${red}错误提示${plain}] 请输入一个数字进行选择"
                continue
            fi
            if [[ "$r_libev_obfs" -lt 1 || "$r_libev_obfs" -gt ${#obfs_libev[@]} ]]; then
                echo -e "[${red}错误提示${plain}] 请输入一个数字进行选择 between 1 and ${#obfs_libev[@]}"
                continue
            fi
            shadowsocklibev_obfs=${obfs_libev[$r_libev_obfs-1]}
            echo
            echo "obfs = ${shadowsocklibev_obfs}"
            echo
            break
            done
        fi
    else
        echo -e "[${yellow}错误提示${plain}] autoconf version is less than 2.67, simple-obfs for ${software[${selected}-1]} installation has been skipped"
    fi
}

install_prepare_gost_user() {
    echo "请设置一个用户名 for ${software[${selected}-1]}"
    read -p "(默认: admin):" gostuser
    [ -z "${gostuser}" ] && gostuser="admin"
    echo
    echo "用户名 = ${gostuser}"
    echo
}

install_prepare_gost_password() {
    echo "请设置一个用户密码 for ${software[${selected}-1]}"
    read -p "(默认: admin):" gostpwd
    [ -z "${gostpwd}" ] && gostpwd="admin"
    echo
    echo "用户密码 = ${gostpwd}"
    echo
}

install_prepare_gost_ip() {
    echo "请设置一个监听地址 for ${software[${selected}-1]}"
    read -p "(默认: 0.0.0.0):" gostaddress
    [ -z "${gostaddress}" ] && gostaddress="0.0.0.0"
    echo
    echo "监听地址 = ${gostaddress}"
    echo
}

install_prepare_gost_port() {
    echo "请设置一个服务端口 ${software[${selected}-1]}"
    read -p "(默认: 1080):" gostport
    [ -z "${gostport}" ] && gostport="1080"
    echo
    echo "监听端口 = ${gostport}"
    echo
}

install_prepare() {

    if  [[ "${selected}" == "1" ]]; then
        install_prepare_password
        install_prepare_port
        install_prepare_cipher
        install_prepare_libev_obfs
    elif [ "${selected}" == "2" ]; then
        install_prepare_gost_user
        install_prepare_gost_password
        install_prepare_gost_ip
        install_prepare_gost_port
    fi

    echo
    echo "Press any key to start...or Press Ctrl+C to cancel"
    char=`get_char`

}

install_main(){
    if   [ "${selected}" == "1" ]; then
        install_shadowsocks
    elif [ "${selected}" == "2" ]; then
        install_gost
    fi

    echo
    echo "Welcome to visit: https://teddysun.com/486.html"
    echo "Enjoy it!"
    echo
}


install_libsodium() {
    if [ ! -f /usr/lib/libsodium.a ]; then
        cd ${DIR}
        download "${libsodium_file}.tar.gz" "${libsodium_url}"
        tar zxf ${libsodium_file}.tar.gz
        cd ${libsodium_file}
        ./configure --prefix=/usr && make && make install
        if [ $? -ne 0 ]; then
            echo -e "[${red}错误提示${plain}] ${libsodium_file} 安装失败!"
            install_cleanup
            exit 1
        fi
    else
        echo -e "[${green}提示信息${plain}] ${libsodium_file} 已经安装"
    fi
}

install_mbedtls() {
    if [ ! -f /usr/lib/libmbedtls.a ]; then
        cd ${DIR}
        download "${mbedtls_file}-gpl.tgz" "${mbedtls_url}"
        tar xf ${mbedtls_file}-gpl.tgz
        cd ${mbedtls_file}
        make SHARED=1 CFLAGS=-fPIC
        make DESTDIR=/usr install
        if [ $? -ne 0 ]; then
            echo -e "[${red}错误提示${plain}] ${mbedtls_file} 安装失败!"
            install_cleanup
            exit 1
        fi
    else
        echo -e "[${green}提示信息${plain}] ${mbedtls_file} 已经安装"
    fi
}

install_shadowsocks_libev() {
    cd ${DIR}
    tar zxf ${shadowsocks_libev_file}.tar.gz
    cd ${shadowsocks_libev_file}
    ./configure --disable-documentation && make && make install
    if [ $? -eq 0 ]; then
        boot_init ${shadowsocks_libev_init} on
    else
        echo
        echo -e "[${red}错误提示${plain}] ${software[0]} 安装失败!"
        echo "请访问: https://teddysun.com/486.html 获取帮助"
        install_cleanup
        exit 1
    fi
}

install_shadowsocks_libev_obfs() {
    if [ "${libev_obfs}" == "y" ] || [ "${libev_obfs}" == "Y" ]; then
        cd ${DIR}
        git clone https://github.com/shadowsocks/simple-obfs.git
        cd simple-obfs
        git submodule update --init --recursive
        ./autogen.sh
        ./configure --disable-documentation
        make
        make install
        if [ ! "$(command -v obfs-server)" ]; then
            echo -e "[${red}错误提示${plain}] simple-obfs for ${software[${selected}-1]} 安装失败."
            echo "请访问: https://teddysun.com/486.html 获取帮助"
            install_cleanup
            exit 1
        fi
    fi
}

install_completed_libev() {
    clear
    ldconfig
    ${shadowsocks_libev_init} start
    echo
    echo -e "恭喜你, ${green}${software[0]}${plain} 代理服务安装部署完成!"
    echo -e "Your Server IP        : ${red} $(get_ip) ${plain}"
    echo -e "Your Server Port      : ${red} ${shadowsocksport} ${plain}"
    echo -e "Your Password         : ${red} ${shadowsockspwd} ${plain}"
    echo -e "Your Encryption Method: ${red} ${shadowsockscipher} ${plain}"
    if [ "$(command -v obfs-server)" ]; then
    echo -e "Your obfs             : ${red} ${shadowsocklibev_obfs} ${plain}"
    fi
    if [ "$fast_open" ]; then
    echo -e "TCP Fast Open         : ${red} ${fast_open} ${plain}"
    fi
}

install_completed_gost() {
    clear
    ${gost_init} start
    echo
    echo -e "恭喜你, ${green}${software[1]}${plain} 代理服务安装部署完成!"
    echo -e "Your Server IP        : ${red} ${gostaddress} ${plain}"
    echo -e "Your Server Port      : ${red} ${gostport} ${plain}"
    echo -e "Your Username         : ${red} ${gostuser} ${plain}"
    echo -e "Your Password: ${red} ${gostpwd} ${plain}"
}

qr_generate_libev() {
    if [ "$(command -v qrencode)" ]; then
        local tmp=$(echo -n "${shadowsockscipher}:${shadowsockspwd}@$(get_ip):${shadowsocksport}" | base64 -w0)
        local qr_code="ss://${tmp}"
        echo
        echo "Your QR Code: (For Shadowsocks Windows, OSX, Android and iOS clients)"
        echo -e "${green} ${qr_code} ${plain}"
        echo -n "${qr_code}" | qrencode -s8 -o ${DIR}/shadowsocks_libev_qr.png
        echo "Your QR Code has been saved as a PNG file path:"
        echo -e "${green} ${DIR}/shadowsocks_libev_qr.png ${plain}"
    fi
}

install_cleanup(){
    cd ${DIR}
    rm -rf simple-obfs
    rm -rf ${libsodium_file} ${libsodium_file}.tar.gz
    rm -rf ${mbedtls_file} ${mbedtls_file}-gpl.tgz
    rm -rf ${shadowsocks_libev_file} ${shadowsocks_libev_file}.tar.gz
    rm -rf ${gost_file} ${gost_file}.tar.gz
}

install_shadowsocks(){
    #echo -e "[${yellow}正在关闭 Selinux...${plain}]"
    #disable_selinux
    install_prepare
    echo -e "[${yellow}正在安装编译依赖...${plain}]"
    install_dependencies
    echo -e "[${yellow}正在下载文件...${plain}]"
    download_files
    echo -e "[${yellow}开始编译 libsodium...${plain}]"
    install_libsodium
    echo -e "[${yellow}设置动态库链接...${plain}]"
    if ! ldconfig -p | grep -wq "/usr/lib"; then
        echo "/usr/lib" > /etc/ld.so.conf.d/lib.conf
    fi
    ldconfig
    echo -e "[${yellow}开始编译 mbedtls...${plain}]"
    install_mbedtls
    echo -e "[${yellow}开始编译 shadowsocks_libev...${plain}]"
    install_shadowsocks_libev
    echo -e "[${yellow}开始编译 shadowsocks_libev_obfs...${plain}]"
    install_shadowsocks_libev_obfs
    echo -e "[${yellow}写出配置文件...${plain}]"
    config_shadowsocks
    if check_sys packageManager yum; then
    echo -e "[${yellow}配置防火墙规则...${plain}]"
        config_firewall ${shadowsocksport}
    fi
    install_completed_libev
    qr_generate_libev
    install_cleanup
}

install_gost(){
    install_prepare
    echo -e "[${yellow}下载文件...${plain}]"
    download_files
    echo -e "[${yellow}解压安装包...${plain}]"
    tar -zxf ${gost_file}.tar.gz||exit $?
    echo -e "[${yellow}移动文件...${plain}]"
    mv ~/${gost_file}/gost /usr/local/bin/gost||exit $?
    echo -e "[${yellow}添加执行权限...${plain}]"
    chmod +x /usr/local/bin/gost||exit $?
    echo -e "[${yellow}写出配置文件中...${plain}]"
    config_gost
    if check_sys packageManager yum; then
    echo -e "[${yellow}配置防火墙规则...${plain}]"
        config_firewall ${gostport}
    fi
    echo -e "[${yellow}配置开机启动中...${plain}]"
    boot_init ${gost_init} on
    install_completed_gost
    install_cleanup
}

uninstall_shadowsocks_libev() {
    printf "你确定卸载 ${red}${software[0]}${plain} ? [y/n]\n"
    read -p "(默认: n):" answer
    [ -z ${answer} ] && answer="n"
    if [ "${answer}" == "y" ] || [ "${answer}" == "Y" ]; then
        ${shadowsocks_libev_init} status > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            boot_init ${shadowsocks_libev_init} off
        fi
        rm -fr $(dirname ${shadowsocks_libev_config})
        rm -f /usr/local/bin/ss-local
        rm -f /usr/local/bin/ss-tunnel
        rm -f /usr/local/bin/ss-server
        rm -f /usr/local/bin/ss-manager
        rm -f /usr/local/bin/ss-redir
        rm -f /usr/local/bin/ss-nat
        rm -f /usr/local/bin/obfs-local
        rm -f /usr/local/bin/obfs-server
        rm -f /usr/local/lib/libshadowsocks-libev.a
        rm -f /usr/local/lib/libshadowsocks-libev.la
        rm -f /usr/local/include/shadowsocks.h
        rm -f /usr/local/lib/pkgconfig/shadowsocks-libev.pc
        rm -f /usr/local/share/man/man1/ss-local.1
        rm -f /usr/local/share/man/man1/ss-tunnel.1
        rm -f /usr/local/share/man/man1/ss-server.1
        rm -f /usr/local/share/man/man1/ss-manager.1
        rm -f /usr/local/share/man/man1/ss-redir.1
        rm -f /usr/local/share/man/man1/ss-nat.1
        rm -f /usr/local/share/man/man8/shadowsocks-libev.8
        rm -fr /usr/local/share/doc/shadowsocks-libev
        rm -f ${shadowsocks_libev_init}
        echo -e "[${green}提示信息${plain}] ${software[0]} 卸载成功"
    else
        echo
        echo -e "[${green}提示信息${plain}] ${software[0]} 卸载取消..."
        echo
    fi
}

uninstall_gost() {
    printf "你确定卸载 ${red}${software[1]}${plain} ? [y/n]\n"
    read -p "(默认: n):" answer
    [ -z ${answer} ] && answer="n"
    if [ "${answer}" == "y" ] || [ "${answer}" == "Y" ]; then
        ${gost_init} status > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            boot_init ${gost_init} off
        fi
        rm -fr ${gost_init}
        rm -fr ${gost_config}
        rm -fr /usr/local/bin/gost
        echo -e "[${green}提示信息${plain}] ${software[1]} 卸载成功!"
    else
        echo
        echo -e "[${green}提示信息${plain}] ${software[1]} 卸载取消..."
        echo
    fi
}

uninstall_select() {
    print_info
    while true
    do
    echo  "您要选择卸载那些代理服务 ?"
    for ((i=1;i<=${#software[@]};i++ )); do
        hint="${software[$i-1]}"
        echo -e "${green}${i}${plain}) ${hint}"
    done
    read -p "请输入一个数字进行选择 [1-2]:" un_select
    case "${un_select}" in
        1|2)
        echo
        echo "你的选择 = ${software[${un_select}-1]}"
        echo
        break
        ;;
        *)
        echo -e "[${red}错误提示${plain}] 请仅输入一个数字 [1-2]"
        ;;
    esac
    done

    if   [ "${un_select}" == "1" ]; then
        if [ -f ${shadowsocks_libev_init} ]; then
            uninstall_shadowsocks_libev
        else
            echo -e "[${red}错误提示${plain}] ${software[${un_select}-1]} 未安装, 请检查后重试."
            echo
            exit 1
        fi
    elif [ "${un_select}" == "2" ]; then
        if [ -f ${gost_init} ]; then
            uninstall_gost
        else
            echo -e "[${red}错误提示${plain}] ${software[${un_select}-1]} 未安装, 请检查后重试."
            echo
            exit 1
        fi
    fi
}

# Initialization step
action=$1
[ -z $1 ] && action=install
case "$action" in
    install|uninstall)
        ${action}_select
        ;;
    *)
        echo "参数错误! [${action}]"
        echo "Usage: `basename $0` [install|uninstall]"
        ;;
esac
