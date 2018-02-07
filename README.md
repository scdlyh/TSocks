# TSocks
[![alt text](http://yaohuo.me/tupian/yaohuo.png "title")](http://yaohuo.me) 
### 一个Android脚本版Shadowsocks启动使用脚本 ### 
- 网络共享数据流量时全部设备走代理 ✔
- 只代理数据网络流量，连接wifi网络时不代理。互不干扰 ✔
- 使用gost进行udp转发达到udp over tcp效果 ✔
- 破大陆的音乐、视频软件，版权地区限制 ✔
- dns解析使用udp不依赖dns解析模块转发 ✔
#### 服务端部署 #### 
一键执行脚本
```
wget --no-check-certificate -O TSocks.sh https://raw.githubusercontent.com/yiguihai/TSocks/master/Server/TSocks-Server.sh
chmod +x TSocks.sh
./TSocks.sh 2>&1 | tee TSocks.log
```
BBR安装脚本
```
wget --no-check-certificate https://github.com/teddysun/across/raw/master/bbr.sh && chmod +x bbr.sh && ./bbr.sh
```

卸载
```
./TSocks.sh uninstall 
```
#### Android使用 #### 
1. 下载好项目文件
2. 解压出Client文件夹，并移动文件夹到/data 或者/system/bin 目录下
3. 将Client目录和文件权限更改为全满 0777
4. 然后执行 “开启.sh” 脚本即可
##### 配置文件 ##### 

- TSocks.conf #脚本主要配置文件
- copyright.acl #https版权问题放行文件
- tsocks.action #http破版权文件

关于版权地区限制：使用了privoxy处理，只要找到中国大陆地区的http类型的ip代理就可以破解(可免), https检测方法需要acl文件配置直连放行。(消耗流量)

腾讯视频与网易云音乐必破，需要经常更换大陆的ip地址，去 
[站大爷](http://ip.zdaye.com/?ip=&port=&adr=&checktime=&sleep=1&cunhuo=&nport=&nadr=&dengji=&https=&yys=&post=%d6%a7%b3%d6&px=3)
随便找个 替换掉tsocks.action文件中的 58.240.53.194:80 这个代理

#### 参考流量转发图 #### 

###### TCP流量 ###### 
浏览器 ⇆ redsocks ⇆ ss-local ⇆ obfs-local 
###### UDP流量 ######
浏览器 ⇆ redsocks2 ⇆ gost ⇆ ss-local ⇆ obfs-local

#### 支持TCP方式解析的DNS ####
#####114 DNS#####
114.114.114.114 114.114.115.115
#####Google DNS#####
8.8.8.8 8.8.4.4
#####IBM Quad9#####
9.9.9.9
#####OpenDNS#####
208.67.222.222 178.79.131.110
### 感谢 ###
秋水逸冰 https://github.com/teddysun/shadowsocks_install
