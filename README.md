# mdig

### 一、软件介绍

从root获取域名的逐级权威服务器，对每个权威服务器都进行解析测试，逐级获取递归服务器。



### 二、编译

`go get github.com/miekg/dns`

`go get golang.org/x/net/publicsuffix`

`go build main.go`



### 三、使用方式

`mdig.go [-dns server] [-type a|aaaa] <domain>`

`mdig -dns 8.8.8.8 -type a www.baidu.com`
