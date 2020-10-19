# **Chap0x01 基于 Scapy 编写端口扫描器**
## **一、实验目的**

* 掌握网络扫描之端口状态探测的基本原理

## **二、实验环境**

* python + scapy

## **三、实验要求**

* 禁止探测互联网上的 IP ，严格遵守网络安全相关法律法规
* 完成以下扫描技术的编程实现
   * TCP connect scan / TCP stealth scan
   * TCP Xmas scan / TCP fin scan / TCP null scan
   * UDP scan
* 上述每种扫描技术的实现测试均需要测试端口状态为：开放、关闭 和 过滤 状态时的程序执行结果
* 提供每一次扫描测试的抓包结果并分析与课本中的扫描方法原理是否相符？如果不同，试分析原因；
* 在实验报告中详细说明实验网络环境拓扑、被测试 IP 的端口状态是如何模拟的
* （可选）复刻 nmap 的上述扫描技术实现的命令行参数开关

## **四、基础知识**

### 关于扫描原理及端口设置

1. TCP Connect Scan：
  * 这种方法最简单，直接连到目标端口并完成一个完整的三次握手过程（SYN, SYN/ACK, 和ACK）。
  * 如果完成了三次握手，则服务器上的端口打开。
  * 如果服务器响应TCP数据包内设置RST标志，则服务器上的端口关闭。
  * 如果服务器无TCP包响应，则端口被过滤。  
    如果服务器使用ICMP数据包type3和ICMP的code1,2,3,9,10或13进行响应，则端口被过滤.
  * 缺点是容易被目标系统检测到。

2. TCP Stealth Scan：
  * 类似于TCP连接扫描。但是最后在TCP数据包中发送的是RST标志而不是RST + ACK。
  * 此技术用于避免防火墙检测端口扫描。

3. TCP XMAS Scan：
  * 在XMAS扫描中，客户端将设置了PSH，FIN和URG标志的TCP数据包和要连接的端口发送到服务器。
  * 如果服务器响应TCP数据包内设置的RST标志，则服务器上的端口关闭。
  * 如果服务器无TCP包响应，无法区分服务器上的端口打开/被过滤。
  * 如果服务器使用ICMP数据包type3和ICMP的code1,2,3,9,10或13进行响应，则端口被过滤.

4. TCP FIN scan： 
  * 这种方法向目标端口发送一个FIN分组。
  * 如果服务器响应TCP数据包内设置的RST标志，则服务器上的端口关闭。
  * 如果服务器无TCP包响应，无法区分服务器上改端口是打开/被过滤。
  * 如果服务器使用ICMP数据包type3和ICMP的code1,2,3,9,10或13进行响应，则端口被过滤.

5. TCP NULL scan：
  * 发送一个没有任何标志位的TCP包给服务器。
  * 如果服务器响应TCP数据包内设置的RST标志，则服务器上的端口关闭。
  * 如果服务器无TCP包响应，无法区分服务器上改端口是打开/被过滤。
  * 如果服务器使用ICMP数据包type3和ICMP的code1,2,3,9,10或13进行响应，则端口被过滤.

6. UDP Scan：
  * 客户端发送一个UDP数据包，其中包含要连接的端口号。
  * 如果服务器使用UDP数据包响应客户端，则该特定端口在服务器上处于打开状态。
  * 如果服务器无UDP包响应，无法区分服务器上改端口是打开/被过滤。
  * 服务器响应ICMP端口不可达错误type3和code3，则端口在服务器上关闭。
  * 如果服务器使用ICMP的type3和code1,2,9,10或13响应客户端，则服务器上的该端口被过滤。

* 端口设置
  * 查看靶机端口状态：netstat -anp
  * 开启80端口： nc -lp 80 
  * 关闭80端口： kill 端口对应的进程ID 
  * 设置防火墙过滤80端口：
    * iptables -L -n 查看本机的iptables设置情况
    * iptables -A INPUT -p tcp -m tcp --dport 80 -j REJECT 开启防火墙对指定端口的过滤（80端口）
    * 关闭防火墙（清空防火墙设置，关闭对80端口的过滤）   
        * iptables -F 清除预设表filter中的所有规则链的规则      
        * iptables -X 清除预设表filter中使用者自定链中的规则   

## **五、实验过程**

###（一）环境搭建
#### 1.拓扑结构  
* 把攻击者主机和靶机放在同一个局域网中
![](pic/网络拓扑.png)  
#### 2.网络配置
* 主机1
![](pic/victim1网络设置.png)    
![](pic/victim1网卡配置.png)
* 主机2
![](pic/victim2网络设置.png)  
![](pic/victim2网卡配置.png) 
#### 3.网络连通测试
* 主机1
![](pic/v1网络连通性.png)  
* 主机2
![](pic/v2网络连通性.png)  

### （二）实验过程
#### 1.端口扫描
* 攻击者对靶机进行端口扫描，没有开放/监听的端口
![](pic/端口80关闭.png)  

#### 2.扫描技术实现
##### (1)TCP connect scan
* 实现原理
    * 如果接收到的是一个 SYN/ACK 数据包，则说明端口是开放状态的；如果接收到的是一个 RST/ACK 数据包，通常意味着端口是关闭的并且链接将会被重置；如果目标主机没有任何响应则意味着目标主机的端口处于过滤状态
    ![](pic/tcp_connect开放状态.png)
    ![](pic/tcp.png)
* 抓包过程
* 端口状态为`关闭`时
    * 主机1进行抓包，将抓包结果存储在本地connect-close.pcap文件
    * 主机1没有开启80/tcp端口时，主机2运行tcp_connect_scan.py文件对主机1进行端口扫描
    * 主机2观察到端口扫描的结果为主机1的80端口为关闭状态
    ![](pic/connect抓包.png)
    * 利用wireshark分析抓包结果
    * 主机2给主机1的80端口发送了设置SYN标志的TCP包
    * 主机1发送给主机2的返回包中设置了RST标志
    * 证明了端口关闭，与课本中的扫描方法原理相符
    ![](pic/connect-close.png)
* 端口状态为`开放`时
    * 打开主机1的80端口监听
    ![](pic/端口80开放.png)
    * 主机1进行抓包，将抓包结果存储在本地connect-open.pcap文件
    * 主机1开启80/tcp端口时，主机2运行tcp_connect_scan.py文件对主机1进行端口扫描
    * 主机2观察到端口扫描的结果为主机1的80端口为开放状态
    ![](pic/connect开放抓包.png)
    * 利用wireshark分析抓包结果
    * 主机1和主机2之间进行了完整的3次握手TCP通信（SYN, SYN/ACK, 和RST）
    * 并且该连接由主机2在最终握手中发送确认ACK+RST标志来建立
    * 证明了端口打开，与课本中的扫描方法原理相符
    ![](pic/connect-open.png)
* 端口状态为`过滤`时
    * 在主机1设置80端口被防火墙过滤
    ![](pic/端口80过滤.png)
    * 主机1进行抓包，将抓包结果存储在本地connect-filter.pcap文件
    * 主机1过滤80/tcp端口时，主机2运行tcp_connect_scan.py文件对主机1进行端口扫描
    * 主机2观察到端口扫描的结果为主机1的80端口为被过滤状态
    ![](pic/connect过滤抓包.png)
    * 利用wireshark分析抓包结果
    * 主机2给主机1的80端口发送了设置SYN标志的TCP包
    * 主机1未返回TCP数据包给攻击者
    * 主机1返回给攻击者一个ICMP数据包，且该包类型为type3
    * 证明了端口被过滤，与课本中的扫描方法原理相符
    ![](pic/connect-filter.png)

##### (2)TCP stealth scan
* 实现原理
    类似于TCP连接扫描。但是最后在TCP数据包中发送的是RST标志而不是RST + ACK。
    ![pic32-2](pic/tcp_stealth开放状态.png)
    ![pic32-3](pic/tcp.png)
* 抓包过程
* 端口状态为`关闭`时
    * 主机1进行抓包，将抓包结果存储在本地stealth-close.pcap文件
    * 主机1没有开启80/tcp端口时，主机2运行tcp_stealth_scan.py文件对主机1进行端口扫描
    * 主机2观察到端口扫描的结果为主机1的80端口为关闭状态
    ![pic32-4](pic/stealth抓包.png)
    * 利用wireshark分析抓包结果
    * 主机2给主机1的80端口发送了设置SYN标志的TCP包
    * 主机1发送给主机2的返回包中设置了RST标志
    * 证明了端口关闭，与课本中的扫描方法原理相符
    ![pic32-5](pic/stealth-close.png)

* 端口状态为`开放`时
    * 主机1进行抓包，将抓包结果存储在本地stealth-open.pcap文件
    * 主机1开启80/tcp端口时，主机2运行tcp_stealth_scan.py文件对主机1进行端口扫描
    * 主机2观察到端口扫描的结果为主机1的80端口为开放状态
    ![pic32-6](pic/stealth开放抓包.png)
    * 利用wireshark分析抓包结果
    * 主机1和主机2之间进行了完整的3次握手TCP通信（SYN, SYN/ACK, 和RST）
    * 并且该连接由主机2在最终握手中发送确认RST标志来建立
    * 证明了端口打开，与课本中的扫描方法原理相符
    ![pic32-7](pic/stealth-open.png)

* 端口状态为`过滤`时
    * 在主机1设置80端口被防火墙过滤
    * 主机1进行抓包，将抓包结果存储在本地stealth-filter.pcap文件
    * 主机1过滤80/tcp端口时，主机2运行tcp_stealth_scan.py文件对主机1进行端口扫描
    * 主机2观察到端口扫描的结果为主机1的80端口为被过滤状态
    ![pic32-8](pic/stealth过滤抓包.png)
    * 利用wireshark分析抓包结果
    * 主机2给主机1的80端口发送了设置SYN标志的TCP包
    * 主机1未返回TCP数据包给攻击者
    * 主机1返回给攻击者一个ICMP数据包，且该包类型为type3
    * 证明了端口被过滤，与课本中的扫描方法原理相符
    ![pic32-9](pic/stealth-filter.png)

##### (3)TCP XMAS scan
* 实现原理
    Xmas发送一个TCP包，并对TCP报文头FIN、URG和PUSH标记进行设置。若是关闭的端口则响应 RST 报文；开放或过滤状态下的端口则无任何响应
    ![pic33-1](pic/tcpxmas关闭.png)
    ![pic33-2](pic/tcpxmas开放.png)
    ![pic33-3](pic/tcpxmas屏蔽.png)
* 抓包过程
* 端口状态为`关闭`时
    * 主机1进行抓包，将抓包结果存储在本地xmas-close.pcap文件
    * 主机1没有开启80/tcp端口时，主机2运行tcp_xmas_scan.py文件对主机1进行端口扫描
    * 主机2观察到端口扫描的结果为主机1的80端口为关闭状态
    ![pic33-4](pic/xmas抓包.png)
    * 利用wireshark分析抓包结果
    * 主机2给主机1的80端口发送了设置了PSH，FIN和URG标志的TCP数据包
    * 主机1发送给主机2的返回包中设置了RST标志
    * 证明了端口关闭，与课本中的扫描方法原理相符
    ![pic33-5](pic/xmas-close.png)

* 端口状态为`开放`时
    * 主机1进行抓包，将抓包结果存储在本地xmas-open.pcap文件
    * 主机1开启80/tcp端口时，主机2运行tcp_xmas_scan.py文件对主机1进行端口扫描
    * 主机2观察到端口扫描的结果为主机1的80端口为开放或被过滤状态
    ![pic33-6](pic/xmas开放抓包.png)
    * 利用wireshark分析抓包结果
    * 主机2给主机1的80端口发送了设置了PSH，FIN和URG标志的TCP数据包
    * 主机1没有发送TCP包响应，无法区分其80端口打开/被过滤
    * 但是主机1也没有发送ICMP数据包给主机2，说明端口不是被过滤状态
    * 证明了端口打开，与课本中的扫描方法原理相符
    ![pic33-7](pic/xmas-open.png)

* 端口状态为`过滤`时
    * 在主机1设置80端口被防火墙过滤
    * 主机1进行抓包，将抓包结果存储在本地xmas-filter.pcap文件
    * 主机1过滤80/tcp端口时，主机2运行tcp_xmas_scan.py文件对主机1进行端口扫描
    * 主机2观察到端口扫描的结果为主机1的80端口为被过滤状态
    ![pic33-8](pic/xmas过滤抓包.png)
    * 利用wireshark分析抓包结果
    * 主机2给主机1的80端口发送了设置了PSH，FIN和URG标志的TCP包
    * 主机1返回给攻击者一个ICMP数据包，且该包类型为type3
    * 证明了端口被过滤，与课本中的扫描方法原理相符
    ![pic33-9](pic/xmas-filter.png)


##### (4)TCP fin scan
* 抓包过程
* 端口状态为`关闭`时
    * 主机1进行抓包，将抓包结果存储在本地fin-close.pcap文件
    * 主机1没有开启80/tcp端口时，主机2运行tcp_fin_scan.py文件对主机1进行端口扫描
    * 主机2观察到端口扫描的结果为主机1的80端口为关闭状态
    ![pic34-4](pic/fin抓包.png)
    * 利用wireshark分析抓包结果
    * 主机2给主机1的80端口发送了设置了FIN标志的TCP数据包
    * 主机1发送给主机2的返回包中设置了RST标志
    * 证明了端口关闭，与课本中的扫描方法原理相符
    ![pic34-5](pic/fin-close.png)

* 端口状态为`开放`时
    * 主机1进行抓包，将抓包结果存储在本地fin-open.pcap文件
    * 主机1开启80/tcp端口时，主机2运行tcp_fin_scan.py文件对主机1进行端口扫描
    * 主机2观察到端口扫描的结果为主机1的80端口为开放或被过滤状态
    ![pic34-6](pic/fin开放抓包.png)
    * 利用wireshark分析抓包结果
    * 主机2给主机1的80端口发送了设置了FIN标志的TCP数据包
    * 主机1没有发送TCP包响应，无法区分其80端口打开/被过滤
    * 但是主机1也没有发送ICMP数据包给主机2，说明端口不是被过滤状态
    * 证明了端口打开，与课本中的扫描方法原理相符
    ![pic34-7](pic/fin-open.png)

* 端口状态为`过滤`时
    * 在主机1设置80端口被防火墙过滤
    * 主机1进行抓包，将抓包结果存储在本地fin-filter.pcap文件
    * 主机1过滤80/tcp端口时，主机2运行tcp_fin_scan.py文件对主机1进行端口扫描
    * 主机2观察到端口扫描的结果为主机1的80端口为被过滤状态
    ![pic34-8](pic/fin过滤抓包.png)
    * 利用wireshark分析抓包结果
    * 主机2给主机1的80端口发送了设置了FIN标志的TCP包
    * 主机1返回给攻击者一个ICMP数据包，且该包类型为type3
    * 证明了端口被过滤，与课本中的扫描方法原理相符
    ![pic34-9](pic/fin-filter.png)

##### (5)TCP null scan
* 抓包过程
* 端口状态为`关闭`时
    * 主机1进行抓包，将抓包结果存储在本地null-close.pcap文件
    * 主机1没有开启80/tcp端口时，主机2运行tcp_null_scan.py文件对主机1进行端口扫描
    * 主机2观察到端口扫描的结果为主机1的80端口为关闭状态
    ![pic35-4](pic/null抓包.png)
    * 利用wireshark分析抓包结果
    * 主机2给主机1的80端口发送了一个没有任何标志位的TCP数据包
    * 主机1发送给主机2的返回包中设置了RST标志
    * 证明了端口关闭，与课本中的扫描方法原理相符
    ![pic35-5](pic/null-close.png)

* 端口状态为`开放`时
    * 主机1进行抓包，将抓包结果存储在本地null-open.pcap文件
    * 主机1开启80/tcp端口时，主机2运行tcp_null_scan.py文件对主机1进行端口扫描
    * 主机2观察到端口扫描的结果为主机1的80端口为开放或被过滤状态
    ![pic35-6](pic/null开放抓包.png)
    * 利用wireshark分析抓包结果
    * 主机2给主机1的80端口发送了一个没有任何标志位的TCP数据包
    * 主机1没有发送TCP包响应，无法区分其80端口打开/被过滤
    * 但是主机1也没有发送ICMP数据包给主机2，说明端口不是被过滤状态
    * 证明了端口打开，与课本中的扫描方法原理相符
    ![pic35-7](pic/null-open.png)

* 端口状态为`过滤`时
    * 在主机1设置80端口被防火墙过滤
    * 主机1进行抓包，将抓包结果存储在本地null-filter.pcap文件
    * 主机1过滤80/tcp端口时，主机2运行tcp_null_scan.py文件对主机1进行端口扫描
    * 主机2观察到端口扫描的结果为主机1的80端口为被过滤状态
    ![pic35-8](pic/null过滤抓包.png)
    * 利用wireshark分析抓包结果
    * 主机2给主机1的80端口发送了一个没有任何标志位的TCP包
    * 主机1返回给攻击者一个ICMP数据包，且该包类型为type3
    * 证明了端口被过滤，与课本中的扫描方法原理相符
    ![pic35-9](pic/null-filter.png)

##### (6)UDP scan
* 实现原理
    如果收到一个 ICMP 不可到达的回应，则认为这个端口是关闭的,对于没有回应的端口则认为是开放的，但是如果目标主机安装有防火墙或其它可以过滤数据包的软硬件,那我们发出 UDP 数据包后,将可能得不到任何回应,我们将会见到所有的被扫描端口都是开放的
    ![pic36-1](pic/udp关闭状态.png)
    ![pic36-2](pic/udp开放状态.png)
* 抓包过程
* 端口状态为`关闭`时
    * 主机1进行抓包，将抓包结果存储在本地udp-close.pcap文件
    * 主机1没有开启80/udp端口时，主机2运行udp_scan.py文件对主机1进行端口扫描
    * 主机2观察到端口扫描的结果为主机1的80端口为关闭状态
    ![pic36-3](pic/udp抓包.png)
    * 利用wireshark分析抓包结果
    * 主机2给主机1的80端口发送了UDP数据包
    * 主机1响应ICMP端口不可达错误type3和code3
    * 证明了端口关闭，与课本中的扫描方法原理相符
    ![pic36-4](pic/udp-close.png)

* 端口状态为`开放`时
    * 打开主机1的80端口监听
    ![pic36-5](pic/udp打开80端口.png)
    * 主机1进行抓包，将抓包结果存储在本地udp-open.pcap文件
    * 主机1开启80/udp端口时，主机2运行udp_scan.py文件对主机1进行端口扫描
    * 主机2观察到端口扫描的结果为主机1的80端口为开放或被过滤状态
    ![pic33-6](pic/udp开放抓包.png)
    * 利用wireshark分析抓包结果
    * 主机2给主机1的80端口发送了UDP数据包
    * 主机1响应ipv4包
    * 证明了端口打开，与课本中的扫描方法原理相符
    ![pic33-7](pic/udp-open.png)

* 端口状态为`过滤`时
    * 结果和端口关闭状态的测试相同

#### 3.复刻 nmap 的上述扫描技术实现的命令行参数开关
##### (1)TCP connect scan
`nmap 172.16.111.103 -p 80 -sT -n -T4 -vv`
##### (2)TCP stealth scan
`nmap 172.16.111.103 -p 80 -sS -n -T4 -vv`
##### (3)TCP Xmas scan
`nmap 172.16.111.103 -p 80 -sX -n -T4 -vv`
##### (4)TCP fin scan
`nmap 172.16.111.103 -p 80 -sF -n -T4 -vv`
##### (5)TCP null scan
`nmap 172.16.111.103 -p 80 -sN -n -T4 -vv`
##### (6)UDP scan
`nmap 172.16.111.103 -p 80 -sU -n -T4 -vv`

### 四、实验总结
#### 1.端口扫描
* 查看端口状态  
`netstat -anp`

* 开放端口
    * TCP  
    `nc -lp 80 &`
    * UDP  
    `nc -u -l -p 80 < /etc/passwd`
* 设置端口被防火墙过滤   
`iptables -A INPUT -p tcp -m tcp --dport 80 -j REJECT`
* 关闭防火墙  
`iptables -F`  
`iptables -X`  
`iptables -L -n`  

#### 2.nmap 常用参数 
* -sT： TCP Connect Scan
* -sS： TCP Stealth Scan
* -sX： TCP XMAS Scan
* -sF： TCP FIN Scan
* -sN： TCP NULL Scan
* -sU： UDP Scan
* -p： port
* -T<0-5>: Set timing template (higher is faster)
* -n： Never do DNS resolution
* -A： Enable OS detection, version detection, script scanning, and traceroute

