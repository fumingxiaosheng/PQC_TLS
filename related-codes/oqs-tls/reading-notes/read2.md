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

> TODO:

1.liboqs中的通用密码套件接口是什么？

2.openssl的server命令行中是否真正使用了kyber，论文里基本上都是使用的密码套件的形式来进行，但是这里却仅仅指定了kex

3.代码的server是否对于配置文件中的内容有新的支持？

# 2024-2-26
1.TLS的handshake过程最后是否会发送finished呢？
2.报错40似乎是因为[TLS的报错机制](https://www.rfc-editor.org/rfc/rfc8446#section-6)
![alt text](image-39.png)

3.TLS协议的再学习
![alt text](image-40.png)
在kex阶段之后，后续的阶段都是被加密了的

client hello和Server hello决定了最终的共享密钥，双方的临时密钥应该放在key_share拓展中
![alt text](image-41.png)

serverhello后面的application data应该都是被加密过了的
![alt text](image-42.png)

# 2024-2-27
1.阅读论文 Benchmarking Post-Quantum Cryptography in TLS

TLS进行密钥交换时，会在supported groups中指明自己支持的组，然后在keyshare中给出待交换的值

kem替代TLS一般的密钥交换时，会clienthello替换keyshare为自己的kem公钥，serverhello替换keyshare为使用kem公钥分装后的临时密钥

混合模式下，openssl（修改了ssl目录）会调用libcrypto下的ECDH算法，以及liboqs下的后量子KEM算法
![alt text](image-43.png)

> TODO:oqs-openssl中到底有没有修改ssl目录来支持进行kem密钥交换呢？

2.阅读论文 Prototyping post-quantum and hybrid key exchange and authentication in TLS and SSH

**每个密码套件包含的信息**
![alt text](image-44.png)

liboqs的**通用密码套件**存在的局限:无法适用于真实的场景中
![alt text](image-45.png)
同时，在论文Post-Quantum Key Exchange for the Internet and the Open Quantum Safe Project中，也提到了liboqs的通用密码套件，其指出，通过在编译时确定liboqs支持的套件中的算法内容，可以只修改liboqs而无需修改ssl目录
![alt text](image-46.png)






**在TLS1.3中集成后量子密码:**
两种协商的方式:1.分别协商单独的算法2.作为一个组合来进行协商（第二种方式往往会引起多余的往返延迟）
> Clienthello的shared_key中允许多个公钥的存在，但是Serverhello中仅仅只允许一个

openssl1.1.1通过**supported groups来定义支持的kex方法**，仅后量子的算法是通过新的标识符来进行协商的，而混合模式的算法则是通过没有结构的标识符来进行协商的
![alt text](image-50.png)
但是，在后面却说到TLS1.3中使用的是点菜式的方法来进行混合(从而避免了组合爆炸的问题)
![alt text](image-49.png)

但是，似乎在新的openssl 1.1.1中，为每一个后量子密码都集成了一个新的标识符
![alt text](image-47.png)


**oqs-openssl的后量子kem调用结构:**
原先的DH调用逻辑是在TLS层调用generate key和generate messae API到crypto层。但是由于KEM方案需要标识客户端和服务端，因此oqs不能仅在crypto层提供kem算法，而需要修改TLS层，来将对于后量子密码方案的调用转移到OQS中
![alt text](image-48.png)

**openssl的应用tip:** 使用装配了oqs-openssl的nginx服务器和s_client完成了新的测试
![alt text](image-51.png)

**新的后量子密码套件的集成思路**:首先加入到liboqs中，根据下面的这段话，再加入到liboqs之后，应该便可以直接使用了。
![alt text](image-52.png)

3.论文阅读 [Post-quantum confidentiality for TLS](https://www.imperialviolet.org/2018/04/11/pqconftls.html)

根据下述文字，在TLS1.2中，客户端和服务端先协商需要使用的密码套件，然后服务端选择其中的一个并发送对应的公钥，而客户端将再使用一个消息来完成密钥的交换；然而在TLS1.3中，客户端会先发送完所有支持的后量子公钥，然后服务端再选择其中的一个进行返回
![alt text](image-53.png)
在TLS1.3中，客户端可以先声明自己支持某个算法，然后服务端再发送额外的消息来让客户端发送对应的公钥
![alt text](image-54.png)

> TODO:验证一下是否符合和真实的TLS1.2和TLS1.3协议的交互流程相一致

kem情况下的密钥交换流程
![alt text](image-55.png)

4.论文阅读 Frodo: Take off the Ring! Practical, Quantum-Secure Key Exchange from LWE


# 2024-2-28

TODO:

1.oqs-openssl中到底有没有修改ssl目录来支持进行kem密钥交换呢？

2.tls 1.3是使用组合的方式来完成kex的嘛

3.验证一下是否符合和真实的TLS1.2和TLS1.3协议的交互流程相一致


**TASK1:调研kem的使用方式**
1.使用命令行中的-groups选项
2.使用C API
[ssl_set1_groups_list](https://www.openssl.org/docs/manmaster/man3/SSL_set1_groups_list.html)用于设置服务端或者客户端支持的组
3.使用openssl.cnf文件来进行配置

再次尝试使用官方文档中生成证书并调用openssl s_server的例子

``` bash
hxw@LAPTOP-QFLFNNQO:~/exp$ openssl s_client -groups frodo640shake
Connecting to ::1
CONNECTED(00000003)
depth=0 CN=test server
verify error:num=20:unable to get local issuer certificate
verify return:1
depth=0 CN=test server
verify error:num=21:unable to verify the first certificate
verify return:1
depth=0 CN=test server
verify return:1
---
Certificate chain
 0 s:CN=test server
   i:CN=test CA
   a:PKEY: UNDEF, 192 (bit); sigalg: dilithium3
   v:NotBefore: Feb 28 02:42:37 2024 GMT; NotAfter: Feb 27 02:42:37 2025 GMT
---
Server certificate
-----BEGIN CERTIFICATE-----
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
AAAAAAACDRchKDE=
-----END CERTIFICATE-----
subject=CN=test server
issuer=CN=test CA
---
No client certificate CA names sent
**Peer signature type: dilithium3**
---
SSL handshake has read 18774 bytes and written 10001 bytes
**Verification error: unable to verify the first certificate**
---
New, TLSv1.3, Cipher is **TLS_AES_256_GCM_SHA384**
Server public key is 192 bit
This TLS version forbids renegotiation.
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 21 (unable to verify the first certificate)
---
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
    Session-ID: A923167F90203A4488998EFC3BA95C40F1E465ED41FD189A6EEF5F24D9D4700D
    Session-ID-ctx: 
    Resumption PSK: 4967084FC519A21F95E5D8EEF8454D48C7668C78FD8A48CD1293C48228133510E6969E693DC4D67FFB7E167E8CE0F87B
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - b4 c3 00 08 4c 40 e6 e7-d5 82 c3 92 a1 f4 65 8a   ....L@........e.
    0010 - e1 67 6d dd 91 82 fa 4d-a1 39 b6 54 c6 8d 93 66   .gm....M.9.T...f
    0020 - 64 01 98 0d 54 57 78 67-43 7e 63 f2 4a 96 56 0b   d...TWxgC~c.J.V.
    0030 - 60 79 53 2a ef 7a ab 2d-f8 ae e3 33 bb 38 ed aa   `yS*.z.-...3.8..
    0040 - cb 09 4f d3 a5 5f c4 c6-22 8d 40 40 82 2d 91 ac   ..O.._..".@@.-..
    0050 - 26 99 59 78 bc ec 17 80-ca c7 c5 02 bb 8a 3b 21   &.Yx..........;!
    0060 - 8b 35 d8 1d af a4 97 f3-44 bf cf f1 16 66 84 59   .5......D....f.Y
    0070 - c8 8c 26 7b 99 34 20 90-f5 82 62 42 08 c4 a8 cc   ..&{.4 ...bB....
    0080 - aa bd ef a5 d0 74 6a 92-18 d6 5d d8 04 39 52 ef   .....tj...]..9R.
    0090 - b2 74 a1 09 7e 73 41 22-39 ea 12 db a1 4b 43 51   .t..~sA"9....KCQ
    00a0 - 5c da bb 82 2a bf 37 db-e4 85 ab 01 70 01 6c 98   \...*.7.....p.l.
    00b0 - c1 1f 67 ab bf fc b3 53-d7 30 43 4d a1 2d 82 f1   ..g....S.0CM.-..
    00c0 - 46 cf 25 59 8d 9a f2 e5-14 fd 2d 28 10 6a 83 ca   F.%Y......-(.j..

    Start Time: 1709088201
    Timeout   : 7200 (sec)
    Verify return code: 21 (unable to verify the first certificate)
    Extended master secret: no
    Max Early Data: 0
---
read R BLOCK
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
    Session-ID: 366F83D7AD98813ADE274F2FD8E113B9E27A3F2662577D93862FC84F33E93E48
    Session-ID-ctx: 
    Resumption PSK: C5B3D5AAE06A4948A3C0B3BA4EB7804A59CE9A884A50322270FFBC38C57385E1BA34A27E3AD3B02DE92D0482B51783D5
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - b4 c3 00 08 4c 40 e6 e7-d5 82 c3 92 a1 f4 65 8a   ....L@........e.
    0010 - f1 98 8c 04 3e 06 a2 1b-e7 1b 2c a3 69 db c7 9d   ....>.....,.i...
    0020 - bc ee ab 19 ed 9e 93 30-fc 72 3a fa 0d c0 3a 7b   .......0.r:...:{
    0030 - a1 2c e0 f8 88 d7 6f d4-2c 09 95 02 a7 99 dc 67   .,....o.,......g
    0040 - 1d 22 08 30 a8 e3 70 94-b0 40 78 22 83 44 1e 49   .".0..p..@x".D.I
    0050 - df 5c 67 30 7b c6 d7 5d-10 39 d4 27 bb 0a 1d 17   .\g0{..].9.'....
    0060 - 28 1c 8f f2 61 27 19 fc-f4 3c ca 8c 7f 81 4b c0   (...a'...<....K.
    0070 - 76 92 b1 c1 39 0b 88 ac-c4 ca 06 83 ee 4a 51 a2   v...9........JQ.
    0080 - f9 39 68 7c 9d 2e f0 c4-c3 60 98 73 cc 7d da ef   .9h|.....`.s.}..
    0090 - 80 82 dc 75 4a 6a 94 d1-37 f9 72 3b 21 f2 00 50   ...uJj..7.r;!..P
    00a0 - a6 de ca a8 76 5a 72 67-16 aa 1a 12 ac a0 9a 5a   ....vZrg.......Z
    00b0 - 0d 14 31 2d f1 5f a6 38-a1 bb ed fd dd ec 9d 5f   ..1-._.8......._
    00c0 - 9d 41 c1 93 4b 22 21 ac-d4 18 c2 d0 36 9a af 53   .A..K"!.....6..S

    Start Time: 1709088201
    Timeout   : 7200 (sec)
    Verify return code: 21 (unable to verify the first certificate)
    Extended master secret: no
    Max Early Data: 0
---
read R BLOCK
GET /
HTTP/1.0 200 ok
Content-type: text/html

<HTML><BODY BGCOLOR="#ffffff">
<pre>

s_server -cert dilithium3_srv.crt -key dilithium3_srv.key -www -tls1_3 -groups kyber768:frodo640shake 
This TLS version forbids renegotiation.

服务端支持的密码套件
Ciphers supported in s_server binary
TLSv1.3    :TLS_AES_256_GCM_SHA384    TLSv1.3    :TLS_CHACHA20_POLY1305_SHA256 
TLSv1.3    :TLS_AES_128_GCM_SHA256    TLSv1.2    :ECDHE-ECDSA-AES256-GCM-SHA384 
TLSv1.2    :ECDHE-RSA-AES256-GCM-SHA384 TLSv1.2    :DHE-RSA-AES256-GCM-SHA384 
TLSv1.2    :ECDHE-ECDSA-CHACHA20-POLY1305 TLSv1.2    :ECDHE-RSA-CHACHA20-POLY1305 
TLSv1.2    :DHE-RSA-CHACHA20-POLY1305 TLSv1.2    :ECDHE-ECDSA-AES128-GCM-SHA256 
TLSv1.2    :ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2    :DHE-RSA-AES128-GCM-SHA256 
TLSv1.2    :ECDHE-ECDSA-AES256-SHA384 TLSv1.2    :ECDHE-RSA-AES256-SHA384   
TLSv1.2    :DHE-RSA-AES256-SHA256     TLSv1.2    :ECDHE-ECDSA-AES128-SHA256 
TLSv1.2    :ECDHE-RSA-AES128-SHA256   TLSv1.2    :DHE-RSA-AES128-SHA256     
TLSv1.0    :ECDHE-ECDSA-AES256-SHA    TLSv1.0    :ECDHE-RSA-AES256-SHA      
SSLv3      :DHE-RSA-AES256-SHA        TLSv1.0    :ECDHE-ECDSA-AES128-SHA    
TLSv1.0    :ECDHE-RSA-AES128-SHA      SSLv3      :DHE-RSA-AES128-SHA        
TLSv1.2    :RSA-PSK-AES256-GCM-SHA384 TLSv1.2    :DHE-PSK-AES256-GCM-SHA384 
TLSv1.2    :RSA-PSK-CHACHA20-POLY1305 TLSv1.2    :DHE-PSK-CHACHA20-POLY1305 
TLSv1.2    :ECDHE-PSK-CHACHA20-POLY1305 TLSv1.2    :AES256-GCM-SHA384         
TLSv1.2    :PSK-AES256-GCM-SHA384     TLSv1.2    :PSK-CHACHA20-POLY1305     
TLSv1.2    :RSA-PSK-AES128-GCM-SHA256 TLSv1.2    :DHE-PSK-AES128-GCM-SHA256 
TLSv1.2    :AES128-GCM-SHA256         TLSv1.2    :PSK-AES128-GCM-SHA256     
TLSv1.2    :AES256-SHA256             TLSv1.2    :AES128-SHA256             
TLSv1.0    :ECDHE-PSK-AES256-CBC-SHA384 TLSv1.0    :ECDHE-PSK-AES256-CBC-SHA  
SSLv3      :SRP-RSA-AES-256-CBC-SHA   SSLv3      :SRP-AES-256-CBC-SHA       
TLSv1.0    :RSA-PSK-AES256-CBC-SHA384 TLSv1.0    :DHE-PSK-AES256-CBC-SHA384 
SSLv3      :RSA-PSK-AES256-CBC-SHA    SSLv3      :DHE-PSK-AES256-CBC-SHA    
SSLv3      :AES256-SHA                TLSv1.0    :PSK-AES256-CBC-SHA384     
SSLv3      :PSK-AES256-CBC-SHA        TLSv1.0    :ECDHE-PSK-AES128-CBC-SHA256 
TLSv1.0    :ECDHE-PSK-AES128-CBC-SHA  SSLv3      :SRP-RSA-AES-128-CBC-SHA   
SSLv3      :SRP-AES-128-CBC-SHA       TLSv1.0    :RSA-PSK-AES128-CBC-SHA256 
TLSv1.0    :DHE-PSK-AES128-CBC-SHA256 SSLv3      :RSA-PSK-AES128-CBC-SHA    
SSLv3      :DHE-PSK-AES128-CBC-SHA    SSLv3      :AES128-SHA                
TLSv1.0    :PSK-AES128-CBC-SHA256     SSLv3      :PSK-AES128-CBC-SHA        
---
双方共同支持的密码套件
Ciphers common between both SSL end points:
TLS_AES_256_GCM_SHA384     TLS_CHACHA20_POLY1305_SHA256 TLS_AES_128_GCM_SHA256    
ECDHE-ECDSA-AES256-GCM-SHA384 ECDHE-RSA-AES256-GCM-SHA384 DHE-RSA-AES256-GCM-SHA384 
ECDHE-ECDSA-CHACHA20-POLY1305 ECDHE-RSA-CHACHA20-POLY1305 DHE-RSA-CHACHA20-POLY1305 
ECDHE-ECDSA-AES128-GCM-SHA256 ECDHE-RSA-AES128-GCM-SHA256 DHE-RSA-AES128-GCM-SHA256 
ECDHE-ECDSA-AES256-SHA384  ECDHE-RSA-AES256-SHA384    DHE-RSA-AES256-SHA256     
ECDHE-ECDSA-AES128-SHA256  ECDHE-RSA-AES128-SHA256    DHE-RSA-AES128-SHA256     
ECDHE-ECDSA-AES256-SHA     ECDHE-RSA-AES256-SHA       DHE-RSA-AES256-SHA        
ECDHE-ECDSA-AES128-SHA     ECDHE-RSA-AES128-SHA       DHE-RSA-AES128-SHA        
AES256-GCM-SHA384          AES128-GCM-SHA256          AES256-SHA256             
AES128-SHA256              AES256-SHA                 AES128-SHA
支持的签名算法:
Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512:ECDSA+SHA224:RSA+SHA224:DSA+SHA224:DSA+SHA256:DSA+SHA384:DSA+SHA512:dilithium2:p256_dilithium2:rsa3072_dilithium2:dilithium3:p384_dilithium3:dilithium5:p521_dilithium5:falcon512:p256_falcon512:rsa3072_falcon512:falcon1024:p521_falcon1024:sphincssha2128fsimple:p256_sphincssha2128fsimple:rsa3072_sphincssha2128fsimple:sphincssha2128ssimple:p256_sphincssha2128ssimple:rsa3072_sphincssha2128ssimple:sphincssha2192fsimple:p384_sphincssha2192fsimple:sphincsshake128fsimple:p256_sphincsshake128fsimple:rsa3072_sphincsshake128fsimple
双方共同支持的签名算法:
Shared Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512:ECDSA+SHA224:RSA+SHA224:dilithium2:p256_dilithium2:rsa3072_dilithium2:dilithium3:p384_dilithium3:dilithium5:p521_dilithium5:falcon512:p256_falcon512:rsa3072_falcon512:falcon1024:p521_falcon1024:sphincssha2128fsimple:p256_sphincssha2128fsimple:rsa3072_sphincssha2128fsimple:sphincssha2128ssimple:p256_sphincssha2128ssimple:rsa3072_sphincssha2128ssimple:sphincssha2192fsimple:p384_sphincssha2192fsimple:sphincsshake128fsimple:p256_sphincsshake128fsimple:rsa3072_sphincsshake128fsimple
**支持的kex方法:
Supported groups: frodo640shake
双方共同支持的kex方法：
Shared groups: frodo640shake** 
注意:当将客户端支持的算法换成kyber768之后，这里会变成对应的kyber768
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
    Session-ID: A608866A89EEDE7710B91AD476CC61D2E986ABAEAFA5CEB361C946A19FBFC23C
    Session-ID-ctx: 01000000
    Resumption PSK: C5B3D5AAE06A4948A3C0B3BA4EB7804A59CE9A884A50322270FFBC38C57385E1BA34A27E3AD3B02DE92D0482B51783D5
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    Start Time: 1709088201
    Timeout   : 7200 (sec)
    Verify return code: 0 (ok)
    Extended master secret: no
    Max Early Data: 0
---
   0 items in the session cache
   0 client connects (SSL_connect())
   0 client renegotiates (SSL_connect())
   0 client connects that finished
   1 server accepts (SSL_accept())
   0 server renegotiates (SSL_accept())
   1 server accepts that finished
   0 session cache hits
   0 session cache misses
   0 session cache timeouts
   0 callback cache hits
   0 cache full overflows (128 allowed)
---
no client certificate available
</pre></BODY></HTML>

closed
```

尝试在命令行使用ctruprime653

客户端的情况如下:
``` bash
hxw@LAPTOP-QFLFNNQO:~/exp$ openssl s_client -groups ctruprime653
Connecting to ::1
CONNECTED(00000003)
[In kem.c] Try to new ctruprime653
[In OQS_KEM_ctruprime_653_new] start new ctruprime 653
1
2
3
[In OQS_KEM_ctruprime_653_new] new ctruprime 653 success,start return!
80B4AE63E37F0000:error:0A000119:SSL routines:tls_get_more_records:decryption failed or bad record mac:ssl/record/methods/tls_common.c:858:
80B4AE63E37F0000:error:0A000139:SSL routines::record layer failure:ssl/record/rec_layer_s3.c:643:
---
no peer certificate available
---
No client certificate CA names sent
---
SSL handshake has read 1039 bytes and written 1306 bytes
Verification: OK
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
This TLS version forbids renegotiation.
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 0 (ok)
---
hxw@LAPTOP-QFLFNNQO:~/exp$ openssl s_client -groups ctrupri
Call to SSL_CONF_cmd(-groups, ctrupri) failed
802420A4DA7F0000:error:0A080106:SSL routines:gid_cb:passed invalid argument:ssl/t1_lib.c:1065:group 'ctrupri' cannot be set
```
服务端的情况如下:
```bash
hxw@LAPTOP-QFLFNNQO:~/exp$ openssl s_client -groups ctruprime653
Connecting to ::1
CONNECTED(00000003)
[In kem.c] Try to new ctruprime653
[In OQS_KEM_ctruprime_653_new] start new ctruprime 653
1
2
3
[In OQS_KEM_ctruprime_653_new] new ctruprime 653 success,start return!
80B4AE63E37F0000:error:0A000119:SSL routines:tls_get_more_records:decryption failed or bad record mac:ssl/record/methods/tls_common.c:858:
80B4AE63E37F0000:error:0A000139:SSL routines::record layer failure:ssl/record/rec_layer_s3.c:643:
---
no peer certificate available
---
No client certificate CA names sent
---
SSL handshake has read 1039 bytes and written 1306 bytes
Verification: OK
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
This TLS version forbids renegotiation.
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 0 (ok)
---
hxw@LAPTOP-QFLFNNQO:~/exp$ openssl s_client -groups ctrupri
Call to SSL_CONF_cmd(-groups, ctrupri) failed
802420A4DA7F0000:error:0A080106:SSL routines:gid_cb:passed invalid argument:ssl/t1_lib.c:1065:group 'ctrupri' cannot be set
```
> 能够识别出ctruprime653，但是却报错mac认证错误。猜测可能是因为ctruprime653的协商出的密钥有问题导致的，因为在调用openssl的kem测试过程中，总是说ctruprime653的测试结果是失败的。所以现在的思路是，确认进行了ctruprime653的协商即可。那么需要寻找能够记录整个协商过程的方式。

尝试使用**sslkeylog**来记录整个过程中使用到的密钥，通过添加SSLKEYLOGFILE环境变量的方式，但是最终并没有输出相应的结果。

[sslkeylog的介绍网址](https://sslkeylog.readthedocs.io/en/latest/index.html)指出，sslkeylog要配合浏览器进行使用，因此可能无法真正得到密钥协商的结果


尝试使用tcpdump来进行抓包，使用下述命令能够记录得到正确抓取的结果
``` bash
sudo tcpdump -i lo -s 0 -w tls13_handshake2.pcap 'tcp port 4433'
```
将抓取形成的pcap文件拷贝到本地主机中，然后使用wireshark查看
![alt text](image-56.png)

对比正常交互过程中的结果
对于frodo640shake,在client hello的key share的拓展中，公钥的长度和声称的是一致的
![alt text](image-57.png)
对于ctruprime653,在client hello的key_share的拓展中，也是一致的
![alt text](image-58.png)

对于ctruprime653,在server hello的key_share的拓展中，也是一致的
![alt text](image-59.png)

目前猜测完成了正确的kex，存在的问题可能是最终得到的kem结果是不一样的

因此，下面再调用liboqs中的内容重新进行测试
![alt text](image-60.png)

在多次的测试结果中，发现最终共享密钥总是不相等，猜测是因为长度的问题

现在的想法是，重新编译一边liboqs，然后进行安装

#### 修改liboqs

![alt text](image-61.png)

![alt text](image-62.png)

在wsl虚拟机上重新安装liboqs,出现如下所示的报错
``` bash
[1186/1216] Linking C executable tests/test_aes
FAILED: tests/test_aes 
: && /usr/bin/cc   -Wl,-z,noexecstack src/common/sha3/xkcp_low/CMakeFiles/xkcp_low_keccakp_1600_plain64.dir/KeccakP-1600/plain-64bits/KeccakP-1600-opt64.c.o src/common/sha3/xkcp_low/CMakeFiles/xkcp_low_keccakp_1600times4_serial.dir/KeccakP-1600times4/serial/KeccakP-1600-times4-on1.c.o src/common/sha3/xkcp_low/CMakeFiles/xkcp_low_keccakp_1600_avx2.dir/KeccakP-1600/avx2/KeccakP-1600-AVX2.S.o src/common/sha3/xkcp_low/CMakeFiles/xkcp_low_keccakp_1600times4_avx2.dir/KeccakP-1600times4/avx2/KeccakP-1600-times4-SIMD256.c.o src/common/CMakeFiles/common.dir/aes/aes.c.o src/common/CMakeFiles/common.dir/aes/aes_c.c.o src/common/CMakeFiles/common.dir/aes/aes128_ni.c.o src/common/CMakeFiles/common.dir/aes/aes256_ni.c.o src/common/CMakeFiles/common.dir/sha2/sha2_ossl.c.o src/common/CMakeFiles/common.dir/sha3/xkcp_sha3.c.o src/common/CMakeFiles/common.dir/sha3/xkcp_sha3x4.c.o src/common/CMakeFiles/common.dir/ossl_helpers.c.o src/common/CMakeFiles/common.dir/common.c.o src/common/CMakeFiles/common.dir/pqclean_shims/nistseedexpander.c.o src/common/CMakeFiles/common.dir/pqclean_shims/fips202.c.o src/common/CMakeFiles/common.dir/pqclean_shims/fips202x4.c.o src/common/CMakeFiles/common.dir/rand/rand.c.o src/common/CMakeFiles/common.dir/rand/rand_nist.c.o tests/CMakeFiles/test_aes.dir/test_aes.c.o  -o tests/test_aes  /usr/lib/x86_64-linux-gnu/libcrypto.so  -lm  -pthread && :
/usr/bin/ld: src/common/CMakeFiles/common.dir/ossl_helpers.c.o: in function `oqs_fetch_ossl_objects':
ossl_helpers.c:(.text.oqs_fetch_ossl_objects+0x14): undefined reference to `EVP_MD_fetch'
/usr/bin/ld: ossl_helpers.c:(.text.oqs_fetch_ossl_objects+0x2b): undefined reference to `EVP_MD_fetch'
/usr/bin/ld: ossl_helpers.c:(.text.oqs_fetch_ossl_objects+0x42): undefined reference to `EVP_MD_fetch'
/usr/bin/ld: ossl_helpers.c:(.text.oqs_fetch_ossl_objects+0x59): undefined reference to `EVP_MD_fetch'
/usr/bin/ld: ossl_helpers.c:(.text.oqs_fetch_ossl_objects+0x70): undefined reference to `EVP_MD_fetch'
/usr/bin/ld: src/common/CMakeFiles/common.dir/ossl_helpers.c.o:ossl_helpers.c:(.text.oqs_fetch_ossl_objects+0x87): more undefined references to `EVP_MD_fetch' follow
/usr/bin/ld: src/common/CMakeFiles/common.dir/ossl_helpers.c.o: in function `oqs_fetch_ossl_objects':
ossl_helpers.c:(.text.oqs_fetch_ossl_objects+0xcc): undefined reference to `EVP_CIPHER_fetch'
/usr/bin/ld: ossl_helpers.c:(.text.oqs_fetch_ossl_objects+0xe3): undefined reference to `EVP_CIPHER_fetch'
/usr/bin/ld: ossl_helpers.c:(.text.oqs_fetch_ossl_objects+0xfa): undefined reference to `EVP_CIPHER_fetch'
/usr/bin/ld: src/common/CMakeFiles/common.dir/ossl_helpers.c.o: in function `oqs_free_ossl_objects':
ossl_helpers.c:(.text.oqs_free_ossl_objects+0x10): undefined reference to `EVP_MD_free'
/usr/bin/ld: ossl_helpers.c:(.text.oqs_free_ossl_objects+0x1c): undefined reference to `EVP_MD_free'
/usr/bin/ld: ossl_helpers.c:(.text.oqs_free_ossl_objects+0x28): undefined reference to `EVP_MD_free'
/usr/bin/ld: ossl_helpers.c:(.text.oqs_free_ossl_objects+0x34): undefined reference to `EVP_MD_free'
/usr/bin/ld: ossl_helpers.c:(.text.oqs_free_ossl_objects+0x40): undefined reference to `EVP_MD_free'
/usr/bin/ld: src/common/CMakeFiles/common.dir/ossl_helpers.c.o:ossl_helpers.c:(.text.oqs_free_ossl_objects+0x4c): more undefined references to `EVP_MD_free' follow
/usr/bin/ld: src/common/CMakeFiles/common.dir/ossl_helpers.c.o: in function `oqs_free_ossl_objects':
ossl_helpers.c:(.text.oqs_free_ossl_objects+0x70): undefined reference to `EVP_CIPHER_free'
/usr/bin/ld: ossl_helpers.c:(.text.oqs_free_ossl_objects+0x7c): undefined reference to `EVP_CIPHER_free'
/usr/bin/ld: ossl_helpers.c:(.text.oqs_free_ossl_objects+0x8c): undefined reference to `EVP_CIPHER_free'
collect2: error: ld returned 1 exit status
[1191/1216] Linking C executable tests/test_hash
FAILED: tests/test_hash 
: && /usr/bin/cc   -Wl,-z,noexecstack src/common/sha3/xkcp_low/CMakeFiles/xkcp_low_keccakp_1600_plain64.dir/KeccakP-1600/plain-64bits/KeccakP-1600-opt64.c.o src/common/sha3/xkcp_low/CMakeFiles/xkcp_low_keccakp_1600times4_serial.dir/KeccakP-1600times4/serial/KeccakP-1600-times4-on1.c.o src/common/sha3/xkcp_low/CMakeFiles/xkcp_low_keccakp_1600_avx2.dir/KeccakP-1600/avx2/KeccakP-1600-AVX2.S.o src/common/sha3/xkcp_low/CMakeFiles/xkcp_low_keccakp_1600times4_avx2.dir/KeccakP-1600times4/avx2/KeccakP-1600-times4-SIMD256.c.o src/common/CMakeFiles/common.dir/aes/aes.c.o src/common/CMakeFiles/common.dir/aes/aes_c.c.o src/common/CMakeFiles/common.dir/aes/aes128_ni.c.o src/common/CMakeFiles/common.dir/aes/aes256_ni.c.o src/common/CMakeFiles/common.dir/sha2/sha2_ossl.c.o src/common/CMakeFiles/common.dir/sha3/xkcp_sha3.c.o src/common/CMakeFiles/common.dir/sha3/xkcp_sha3x4.c.o src/common/CMakeFiles/common.dir/ossl_helpers.c.o src/common/CMakeFiles/common.dir/common.c.o src/common/CMakeFiles/common.dir/pqclean_shims/nistseedexpander.c.o src/common/CMakeFiles/common.dir/pqclean_shims/fips202.c.o src/common/CMakeFiles/common.dir/pqclean_shims/fips202x4.c.o src/common/CMakeFiles/common.dir/rand/rand.c.o src/common/CMakeFiles/common.dir/rand/rand_nist.c.o tests/CMakeFiles/test_hash.dir/test_hash.c.o  -o tests/test_hash  /usr/lib/x86_64-linux-gnu/libcrypto.so  -lm  -pthread && :
/usr/bin/ld: src/common/CMakeFiles/common.dir/ossl_helpers.c.o: in function `oqs_fetch_ossl_objects':
ossl_helpers.c:(.text.oqs_fetch_ossl_objects+0x14): undefined reference to `EVP_MD_fetch'
/usr/bin/ld: ossl_helpers.c:(.text.oqs_fetch_ossl_objects+0x2b): undefined reference to `EVP_MD_fetch'
/usr/bin/ld: ossl_helpers.c:(.text.oqs_fetch_ossl_objects+0x42): undefined reference to `EVP_MD_fetch'
/usr/bin/ld: ossl_helpers.c:(.text.oqs_fetch_ossl_objects+0x59): undefined reference to `EVP_MD_fetch'
/usr/bin/ld: ossl_helpers.c:(.text.oqs_fetch_ossl_objects+0x70): undefined reference to `EVP_MD_fetch'
/usr/bin/ld: src/common/CMakeFiles/common.dir/ossl_helpers.c.o:ossl_helpers.c:(.text.oqs_fetch_ossl_objects+0x87): more undefined references to `EVP_MD_fetch' follow
/usr/bin/ld: src/common/CMakeFiles/common.dir/ossl_helpers.c.o: in function `oqs_fetch_ossl_objects':
ossl_helpers.c:(.text.oqs_fetch_ossl_objects+0xcc): undefined reference to `EVP_CIPHER_fetch'
/usr/bin/ld: ossl_helpers.c:(.text.oqs_fetch_ossl_objects+0xe3): undefined reference to `EVP_CIPHER_fetch'
/usr/bin/ld: ossl_helpers.c:(.text.oqs_fetch_ossl_objects+0xfa): undefined reference to `EVP_CIPHER_fetch'
/usr/bin/ld: src/common/CMakeFiles/common.dir/ossl_helpers.c.o: in function `oqs_free_ossl_objects':
ossl_helpers.c:(.text.oqs_free_ossl_objects+0x10): undefined reference to `EVP_MD_free'
/usr/bin/ld: ossl_helpers.c:(.text.oqs_free_ossl_objects+0x1c): undefined reference to `EVP_MD_free'
/usr/bin/ld: ossl_helpers.c:(.text.oqs_free_ossl_objects+0x28): undefined reference to `EVP_MD_free'
/usr/bin/ld: ossl_helpers.c:(.text.oqs_free_ossl_objects+0x34): undefined reference to `EVP_MD_free'
/usr/bin/ld: ossl_helpers.c:(.text.oqs_free_ossl_objects+0x40): undefined reference to `EVP_MD_free'
/usr/bin/ld: src/common/CMakeFiles/common.dir/ossl_helpers.c.o:ossl_helpers.c:(.text.oqs_free_ossl_objects+0x4c): more undefined references to `EVP_MD_free' follow
/usr/bin/ld: src/common/CMakeFiles/common.dir/ossl_helpers.c.o: in function `oqs_free_ossl_objects':
ossl_helpers.c:(.text.oqs_free_ossl_objects+0x70): undefined reference to `EVP_CIPHER_free'
/usr/bin/ld: ossl_helpers.c:(.text.oqs_free_ossl_objects+0x7c): undefined reference to `EVP_CIPHER_free'
/usr/bin/ld: ossl_helpers.c:(.text.oqs_free_ossl_objects+0x8c): undefined reference to `EVP_CIPHER_free'
collect2: error: ld returned 1 exit status
[1202/1216] Building C object src/sig/falcon/CMakeFiles/falcon_512_avx2.dir/pqclean_falcon-512_avx2/keygen.c.o
ninja: build stopped: subcommand failed.
```

似乎在直接使用oqs-provider-hxw进行安装的过程中，也会出现类似的错误

## 2024-3-1
感觉上述错误应该是由于没有找到对应的openssl引起的。
根据以前的报错，应该是openssl的版本问题的错误。
![alt text](image-63.png)

通过指定openssl_root_dir来使得liboqs针对具体的openssl版本进行安装
``` bash
cmake -GNinja .. -DOPENSSL_ROOT_DIR=/home/hxw/oqs-provider-hxw/.local/
```

调整并编译成功后，得到了正确的ctruprime653的结果
```bash
hxw@LAPTOP-QFLFNNQO:~/exp/liboqs-test/liboqs-hxw/build/tests$ ./test_kem ctruprime653
Testing KEM algorithms using liboqs version 0.10.0-dev
Configuration info
==================
Target platform:  x86_64-Linux-5.10.16.3-microsoft-standard-WSL2
Compiler:         gcc (9.4.0)
Compile options:  [-Wa,--noexecstack;-O3;-fomit-frame-pointer;-fdata-sections;-ffunction-sections;-Wl,--gc-sections;-Wbad-function-cast]
OQS version:      0.10.0-dev
Git commit:       
OpenSSL enabled:  Yes (OpenSSL 3.3.0-dev )
AES:              NI
SHA-2:            OpenSSL
SHA-3:            C
OQS build flags:  OQS_DIST_BUILD OQS_OPT_TARGET=generic CMAKE_BUILD_TYPE=Release 
CPU exts active:  ADX AES AVX AVX2 BMI1 BMI2 PCLMULQDQ POPCNT SSE SSE2 SSE3
[In kem.c] Try to new ctruprime653
[In OQS_KEM_ctruprime_653_new] start new ctruprime 653
================================================================================
Sample computation for KEM Ctruprime653
================================================================================
shared secrets are equal
```

**重新安装一遍oqs_provider**
首先修改命令，使得对于openssl版本的检测失效，来重新安装新的openssl
![alt text](image-64.png)

在安装过程中，出现如下所示的报错
```bash
[1216/1216] Linking C executable tests/kat_kem
[0/1] Install the project...
-- Install configuration: ""
-- Installing: /home/hxw/exp/oqs-provider-test/oqs-provider-hxw/scripts/.local/lib/cmake/liboqs/liboqsConfig.cmake
-- Installing: /home/hxw/exp/oqs-provider-test/oqs-provider-hxw/scripts/.local/lib/cmake/liboqs/liboqsConfigVersion.cmake
-- Installing: /home/hxw/exp/oqs-provider-test/oqs-provider-hxw/scripts/.local/lib/pkgconfig/liboqs.pc
-- Installing: /home/hxw/exp/oqs-provider-test/oqs-provider-hxw/scripts/.local/lib/liboqs.a
-- Installing: /home/hxw/exp/oqs-provider-test/oqs-provider-hxw/scripts/.local/lib/cmake/liboqs/liboqsTargets.cmake
-- Installing: /home/hxw/exp/oqs-provider-test/oqs-provider-hxw/scripts/.local/lib/cmake/liboqs/liboqsTargets-noconfig.cmake
-- Installing: /home/hxw/exp/oqs-provider-test/oqs-provider-hxw/scripts/.local/include/oqs/oqs.h
-- Installing: /home/hxw/exp/oqs-provider-test/oqs-provider-hxw/scripts/.local/include/oqs/common.h
-- Installing: /home/hxw/exp/oqs-provider-test/oqs-provider-hxw/scripts/.local/include/oqs/rand.h
-- Installing: /home/hxw/exp/oqs-provider-test/oqs-provider-hxw/scripts/.local/include/oqs/aes.h
-- Installing: /home/hxw/exp/oqs-provider-test/oqs-provider-hxw/scripts/.local/include/oqs/sha2.h
-- Installing: /home/hxw/exp/oqs-provider-test/oqs-provider-hxw/scripts/.local/include/oqs/sha3.h
-- Installing: /home/hxw/exp/oqs-provider-test/oqs-provider-hxw/scripts/.local/include/oqs/sha3x4.h
-- Installing: /home/hxw/exp/oqs-provider-test/oqs-provider-hxw/scripts/.local/include/oqs/kem.h
-- Installing: /home/hxw/exp/oqs-provider-test/oqs-provider-hxw/scripts/.local/include/oqs/sig.h
-- Installing: /home/hxw/exp/oqs-provider-test/oqs-provider-hxw/scripts/.local/include/oqs/kem_bike.h
-- Installing: /home/hxw/exp/oqs-provider-test/oqs-provider-hxw/scripts/.local/include/oqs/kem_frodokem.h
-- Installing: /home/hxw/exp/oqs-provider-test/oqs-provider-hxw/scripts/.local/include/oqs/kem_ntruprime.h
-- Installing: /home/hxw/exp/oqs-provider-test/oqs-provider-hxw/scripts/.local/include/oqs/kem_classic_mceliece.h
-- Installing: /home/hxw/exp/oqs-provider-test/oqs-provider-hxw/scripts/.local/include/oqs/kem_hqc.h
-- Installing: /home/hxw/exp/oqs-provider-test/oqs-provider-hxw/scripts/.local/include/oqs/kem_kyber.h
-- Installing: /home/hxw/exp/oqs-provider-test/oqs-provider-hxw/scripts/.local/include/oqs/kem_ctruprime.h
-- Installing: /home/hxw/exp/oqs-provider-test/oqs-provider-hxw/scripts/.local/include/oqs/sig_dilithium.h
-- Installing: /home/hxw/exp/oqs-provider-test/oqs-provider-hxw/scripts/.local/include/oqs/sig_falcon.h
-- Installing: /home/hxw/exp/oqs-provider-test/oqs-provider-hxw/scripts/.local/include/oqs/sig_sphincs.h
-- Installing: /home/hxw/exp/oqs-provider-test/oqs-provider-hxw/scripts/.local/include/oqs/oqsconfig.h
oqsprovider (_build/lib/oqsprovider.so) not built: Building...
openssl install type
CMake Error: The source directory "/home/hxw/exp/oqs-provider-test/oqs-provider-hxw/scripts" does not appear to contain CMakeLists.txt.
Specify --help for usage, or press the help button on the CMake GUI.
before cmake
Error: /home/hxw/exp/oqs-provider-test/oqs-provider-hxw/scripts/_build is not a directory
provider build failed. Exiting.
```

发现错误的原因在于安装的位置错误，不应该在scripts文件夹下，而应该在最外面的文件夹下。在修改了这个问题之后，正确编译成功。

**下面尝试修改环境变量，来将openssl指向新编译成功的版本**
首先记录一下修改之前的环境变量值
``` sh
export OPENSSL_PATH=/home/hxw/oqs-provider-hxw/.local/bin
export PATH=$OPENSSL_PATH:$PATH
export LD_LIBRARY_PATH=/home/hxw/oqs-provider-hxw/.local/lib64
export OPENSSL_APP=/home/hxw/oqs-provider-hxw/openssl/apps/openssl
export OPENSSL_CONF=/home/hxw/oqs-provider-hxw/scripts/openssl-ca.cnf
export OPENSSL_MODULES=/home/hxw/oqs-provider-hxw/_build/lib
export C_INCLUDE_PATH=$C_INCLUDE_PATH:/home/hxw/oqs-provider-hxw/.local/include
```

修改后的系统环境变量如下所示
``` sh
export OPENSSL_PATH=~/exp/oqs-provider-test/oqs-provider-hxw/.local/bin
export PATH=$OPENSSL_PATH:$PATH
export LD_LIBRARY_PATH=/home/hxw/oqs-provider-hxw/.local/lib64
export OPENSSL_APP=~/exp/oqs-provider-test/oqs-provider-hxw/openssl/apps/openssl
export OPENSSL_CONF=~/exp/oqs-provider-test/oqs-provider-hxw/scripts/openssl-ca.cnf
export OPENSSL_MODULES=/home/hxw/oqs-provider-hxw/_build/lib
export C_INCLUDE_PATH=$C_INCLUDE_PATH:/home/hxw/oqs-provider-hxw/.local/include
```

但是修改了之后，还是没有转变对应的版本
``` bash
hxw@LAPTOP-QFLFNNQO:~/exp$ openssl version -d
OPENSSLDIR: "/home/hxw/oqs-provider-hxw/.local/ssl"
```
注:此时使用openssl的s_server和s_client进行验证，并没有损坏原先安装好的openssl

在老虚拟机上，记录下的对于系统环境变量设置的思考

![alt text](image-65.png)
猜测是因为PATH中没有删除掉原先的环境变量，但是通过查看PATH的值，发现并不存在这个问题
``` bash
hxw@LAPTOP-QFLFNNQO:~/exp/certs$ printenv PATH | grep /home/hxw/oqs-provider-hxw/.local/bin
hxw@LAPTOP-QFLFNNQO:~/exp/certs$ printenv PATH | grep ~/exp/oqs-provider-test/oqs-provider-hxw/.local/bin
/home/hxw/.vscode-server/bin/903b1e9d8990623e3d7da1df3d33db3e42d80eda/bin/remote-cli:/home/hxw/exp/oqs-provider-test/oqs-provider-hxw/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/usr/lib/wsl/lib:/mnt/e/VMware/bin/:/mnt/c/Windows/system32:/mnt/c/Windows:/mnt/c/Windows/System32/Wbem:/mnt/c/Windows/System32/WindowsPowerShell/v1.0/:/mnt/c/Windows/System32/OpenSSH/:/mnt/e/Git/bin/:/mnt/c/Users/Lenovo/AppData/Local/Microsoft/WindowsApps:/mnt/e/VsCode/Microsoft VS Code/bin:/snap/bin
```
通过直接在openssl命令前面加上路径来使用对应的openssl
```bash
hxw@LAPTOP-QFLFNNQO:~/exp/certs$ /home/hxw/exp/oqs-provider-test/oqs-provider-hxw/.local/bin/openssl s_client -groups ctruprime653
Connecting to ::1
CONNECTED(00000003)
[In kem.c] Try to new ctruprime653
[In OQS_KEM_ctruprime_653_new] start new ctruprime 653
1
2
3
[In OQS_KEM_ctruprime_653_new] new ctruprime 653 success,start return!
8064F5D0A17F0000:error:0A000119:SSL routines:tls_get_more_records:decryption failed or bad record mac:ssl/record/methods/tls_common.c:858:
8064F5D0A17F0000:error:0A000139:SSL routines::record layer failure:ssl/record/rec_layer_s3.c:643:
---
no peer certificate available
---
No client certificate CA names sent
---
SSL handshake has read 1037 bytes and written 1306 bytes
Verification: OK
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
This TLS version forbids renegotiation.
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 0 (ok)
---
```
但是仍然报错，根据输出的ctruprime信息，观察到在调用liboqs库的过程中，仍然使用的是老版本的liboqs，猜测是和liboqs指定的路径有关



晚上回来进行检查，发现可能当时自己看错了？直接调用新版openssl中bin的命令并不能解决版本调用的问题
``` bash
hxw@LAPTOP-QFLFNNQO:~/exp/oqs-provider-test/oqs-provider-hxw/.local/bin$ ./openssl version -d
OPENSSLDIR: "/home/hxw/oqs-provider-hxw/.local/ssl"
```

在尝试修改环境变量OPENSSLDIR的情况下也是如此
``` bash
hxw@LAPTOP-QFLFNNQO:~/exp/oqs-provider-test/oqs-provider-hxw/.local/bin$ openssl version -d
OPENSSLDIR: "/home/hxw/oqs-provider-hxw/.local/ssl"
hxw@LAPTOP-QFLFNNQO:~/exp/oqs-provider-test/oqs-provider-hxw/.local/bin$ printenv OPENSSLDIR
/home/hxw/exp/oqs-provider-test/oqs-provider-hxw/.local/ssl
```
TODO:找到能够修改已知openssl使用版本的方法，并测试修改后的ctruprime是否有用

