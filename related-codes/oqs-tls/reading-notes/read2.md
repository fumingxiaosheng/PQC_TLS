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