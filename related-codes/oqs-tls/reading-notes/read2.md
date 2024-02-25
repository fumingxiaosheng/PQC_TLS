## 2024-2-23
TODO:寻找ssl协议中关于指定协商算法的位置

related-codes\oqs-tls\openssl-master\ssl中存放了tls相关协议的流程

related-codes\oqs-tls\openssl-master\demos\http3展示了一个示例

从handshake入手
bio_ssl.c中给出了诸如ssl_read等的实现函数

在ssl_local.h中，给出了CLIENTHELLO_MSG的相关结构体

``` cpp
typedef struct {
    unsigned int isv2;
    unsigned int legacy_version;
    unsigned char random[SSL3_RANDOM_SIZE];
    size_t session_id_len;
    unsigned char session_id[SSL_MAX_SSL_SESSION_ID_LENGTH];
    size_t dtls_cookie_len;
    unsigned char dtls_cookie[DTLS1_COOKIE_LENGTH];
    PACKET ciphersuites;
    size_t compressions_len;
    unsigned char compressions[MAX_COMPRESSIONS_SIZE];
    PACKET extensions;
    size_t pre_proc_exts_len;
    RAW_EXTENSION *pre_proc_exts;
} CLIENTHELLO_MSG;
```


函数 [SSL_CTX_set_ciphersuites](https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set_ciphersuites.html)和 [SSL_CTX_set_cipher_list](https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set_cipher_list.html)仅仅只是指定了记录层使用到的加密算法的密码套件的类型，而不是kem的

注释掉connect.cnf的第一个配置后，出现如下所示的报错
![alt text](image-29.png)
然后把accept.cnf中的第一个配置也给注释掉


``` bash
hxw@LAPTOP-QFLFNNQO:~/exp/demos/bio$ ./client-conf
Error connecting to server
140042944201344:error:14094410:SSL routines:ssl3_read_bytes:sslv3 alert handshake failure:../ssl/record/rec_layer_s3.c:1543:SSL alert number 40

hxw@LAPTOP-QFLFNNQO:~/exp/demos/bio$ ./server-conf
[Stage 1]
[Stage 2]In for
[Stage 3]In for i=-1
140062391857792:error:14201076:SSL routines:tls_choose_sigalg:no suitable signature algorithm:../ssl/t1_lib.c:2750:
```

尝试修改对应的编译选项，仍然会出现上面的报错

翻阅上述报错在ssl中对应的源码，服务端的看不太懂，客户端的指示存在握手的错误
![alt text](image-30.png)

根据服务端的报错，不支持对应的签名算法，那么看一下非conf版本的代码

![alt text](image-31.png)

在注释掉对于签名算法的要求之后，发现能够使用，但是通过tcpdump无法抓包成功

开始在vm虚拟机上安装wireshark，企图正确抓包并进行分析

在1.更改了系统环境变量2.安装wireshark的情况下，能够抓到正确的包
![alt text](image-32.png)

[对TLS包进行分析的博客](https://blog.csdn.net/simonchi/article/details/107563574)

# 2024-2-25
1.通过配置文件来修改默认的密钥协商方式

[SSL_CONF_cmd](https://www.openssl.org/docs/man3.0/man3/SSL_CONF_cmd.html)重要信息提取：
(1)命令行参数:
-serverpref
Use server and not client preference order when determining which **cipher suite**, **signature algorithm** or **elliptic curve** to use for an incoming connection. 
-sigalgs
用于设置服务端或者客户端支持哪些签名算法
在未设置的情况下，默认为Openssl库支持的所有算法
设置的语法规则:
The algs argument should be a colon separated list of signature algorithms in order of decreasing preference of the form algorithm+hash or signature_scheme. algorithm is one of RSA, DSA or ECDSA and hash is a supported algorithm OID short name such as SHA1, SHA224, SHA256, SHA384 of SHA512. Note: algorithm and hash names are case sensitive. signature_scheme is one of the signature schemes defined in TLSv1.3, specified using the IETF name, e.g., ecdsa_secp256r1_sha256, ed25519, or rsa_pss_pss_sha256.

-groups:
用于决定签名和kex使用的group
Currently supported groups for TLSv1.3 are P-256, P-384, P-521, X25519, X448, ffdhe2048, ffdhe3072, ffdhe4096, ffdhe6144, ffdhe8192.

-ciphersuites:
用于设置TLS1.3的密码套件
[密码套件的格式IANA](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4):以冒号分隔(没什么用，仅仅只是列出了一些描述对应的参考文档)

[具体的格式 CIPHER LIST FORMAT](https://www.openssl.org/docs/man3.0/man1/openssl-ciphers.html):
可以使用SHA来代表整个SHA族的算法；可以使用逻辑表达式的形式，+代表逻辑与，!代表非等(例如 openssl ciphers -s -v 'ALL:@SECLEVEL=2' 用于列出所有安全等级为2的密码套件)，来对默认支持的算法列表进行操作

![alt text](image-33.png)


[openssl-ciphers命令](https://www.openssl.org/docs/manmaster/man1/openssl-ciphers.html)
``` bash
hxw@LAPTOP-QFLFNNQO:~/exp$ openssl ciphers -s
TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA

openssl ciphers -ciphersuites TLS_AES_256_GCM_SHA384

```

> 总结:在密码套件中确实指定了kex的方式，但是似乎默认的kex中并没有kem的部分，基本上都是RSA、ECDH之类的这种，具体可以参照openssl-ciphers这个网址

还没找到具体的格式进行对应，还没有显示oqsprovider的作用


> Openssl OID name:prime256v1

(2) 配置文件参数
-Ciphersuites:
TLS1.3支持的参数

-SignatureAlgorithm:
客户端和服务端代表支持的签名算法
The value argument should be a colon separated list of signature algorithms in order of decreasing preference of the form ****algorithm+hash or signature_scheme**. **algorithm is one of RSA, DSA or ECDSA** and **hash is a supported algorithm OID short name such as SHA1, SHA224, SHA256, SHA384 of SHA512**. Note: algorithm and hash names are case sensitive. signature_scheme is one of the signature schemes defined in TLSv1.3, specified using the IETF name, e.g., ecdsa_secp256r1_sha256, ed25519, or rsa_pss_pss_sha256.

>为什么在实验的过程中显示不支持该签名算法呢？

-Groups/Curves
用于设置签名和kex的椭圆曲线组

-VerifyMode
用于设置对于客户端的认证方式

-ClientCAFile ClientCAPath
服务端指定的对于客户端的证书的要求

(3)编程示例
设置支持的签名算法
``` cpp
SSL_CONF_cmd(ctx, "SignatureAlgorithms", "ECDSA+SHA256:RSA+SHA256:DSA+SHA256");
```

> 总结:可以通过配置文件、命令行以及编程的方式来设置最初的handshake过程中需要交换的信息，但是还没有找到一个通用的方式来进行设置

(4) 编程实战
修改支持的签名算法后，观察到wireshark中仅仅支持自己指定的签名算法
![alt text](image-35.png)
但是可能是出于服务端的证书的原因，导致服务端报错无法支持现有的签名算法
同时，并没有相关的证书的信息

观察了csdn上对于某一次交互过程的解析，发现博客上的交互过程和自己截取到的不太一样，不存在证书的交换等过程


2.观察截取的报文
发现里面添加了新的后量子的密码
![alt text](image-34.png)

TODO:去看一下openssl-oqs里面是如何定义对于后量子密码的支持的

[OpenSSL Strategic Architecture](https://www.openssl.org/docs/OpenSSLStrategicArchitecture.html)

[OpenSSL1.1.0中关于后量子密码的支持](https://github.com/open-quantum-safe/openssl/blob/OQS-OpenSSL_1_1_1-stable/README.md)

按照论文里的内容，应该是已经实现了对于后量子密码的支持了的
![alt text](image-36.png)

基于[oqs provider中的示例](https://github.com/open-quantum-safe/oqs-provider/blob/main/USAGE.md#running-a-client-to-interact-with-quantum-safe-kem-algorithms)，尝试使用后量子密码进行交互，但是抓包抓不到，而且似乎密码套件并没有引入诸如kyber等后量子密码的信息

后量子的签名倒是可以找到相关的信息
![alt text](image-37.png)

对于group选项给出一些奇怪的东西，是能够正确识别的，但是在抓包的过程中就是无法正确地进行识别
![alt text](image-38.png)

TODO:
1.liboqs中的通用密码套件接口是什么？
2.openssl的server命令行中是否真正使用了kyber
3.代码的server是否对于配置文件中的内容有新的支持？