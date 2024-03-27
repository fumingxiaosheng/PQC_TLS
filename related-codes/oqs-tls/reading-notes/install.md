# 基础使用
**step1**:在oqs-provider-hxw文件夹下，运行
``` bash
./scripts/fullbuild.sh
```

**step2**:
修改/etc/profile文件
```bash
sudo vim /etc/profile

export OPENSSL_PATH=/home/hxw/Desktop/TLS-hxw/oqs-provider-hxw/.local/bin
export PATH=$OPENSSL_PATH:$PATH
export LD_LIBRARY_PATH=/home/hxw/Desktop/TLS-hxw/oqs-provider-hxw/.local/lib64
export OPENSSL_APP=/home/hxw/Desktop/TLS-hxw/oqs-provider-hxw/openssl/apps/openssl
export OPENSSL_CONF=/home/hxw/Desktop/TLS-hxw/oqs-provider-hxw/scripts/openssl-ca.cnf
export OPENSSL_MODULES=/home/hxw/Desktop/TLS-hxw/oqs-provider-hxw/_build/lib
export C_INCLUDE_PATH=$C_INCLUDE_PATH:/home/hxw/Desktop/TLS-hxw/oqs-provider-hxw/.local/include

export OPENSSLDIR=/home/hxw/Desktop/TLS-hxw/oqs-provider-hxw/.local/ssl

source /etc/profile
```

export OPENSSL_PATH=/home/hxw/Desktop/TLS-hxw/oqs-provider-hxw-batch/.local/bin
export PATH=$OPENSSL_PATH:$PATH
export LD_LIBRARY_PATH=/home/hxw/Desktop/TLS-hxw/oqs-provider-hxw-batch/.local/lib64
export OPENSSL_APP=/home/hxw/Desktop/TLS-hxw/oqs-provider-hxw-batch/openssl/apps/openssl
export OPENSSL_CONF=/home/hxw/Desktop/TLS-hxw/oqs-provider-hxw-batch/scripts/openssl-ca.cnf
export OPENSSL_MODULES=/home/hxw/Desktop/TLS-hxw/oqs-provider-hxw-batch/_build/lib
export C_INCLUDE_PATH=$C_INCLUDE_PATH:/home/hxw/Desktop/TLS-hxw/oqs-provider-hxw-batch/.local/include

export OPENSSLDIR=/home/hxw/Desktop/TLS-hxw/oqs-provider-hxw-batch/.local/ssl

**step3**:检查版本安装是否正确
``` bash
openssl version -d
```
**step4**:
首先准备好抓包
``` bash
sudo tcpdump -i lo -s 0 -w tls13_handshake2.pcap 'tcp port 4433'
```

然后调用openssl中的命令完成server和client的交互
``` bash
openssl s_server -cert dilithium3_srv.crt -key dilithium3_srv.key -www -tls1_3 -groups kyber768:ctruprime653

openssl s_client -groups ctruprime653
```

# 网络环境的搭建
**step1**:开启ipv4的转发，开启后重启以生效
```bash
sudo vi /etc/sysctl.conf
sudo sysctl -p /etc/sysctl.conf
```

**step2**:搭建网络环境并测试联通性质
```bash
sudo ./platform.install.sh
sudo ip netns exec ns1 ping 10.1.3.3
```

**step3**:重新在命名空间中创建新的bash
```bash
sudo ip netns exec ns1 bash
sudo ip netns exec ns2 bash
```
在每个bash中执行如下命令
```bash
source /etc/profile
```

**step4**:运行server和client
```bash
openssl s_server -cert dilithium3_srv.crt -key dilithium3_srv.key -www -tls1_3 -groups ctruprime653

openssl s_client -groups ctruprime653 -connect 10.1.2.2:4433
```
使用-connect指定服务器的ip和端口

# nginx服务器
step1:安装nginx服务器
```bash
sudo apt-get install libpcre3 libpcre3-dev

CFLAGS="-Wno-error=deprecated-declarations" ./configure --prefix=/home/hxw/Desktop/TLS-hxw/benchmark-platform/nginx-1.17.5/hxw_nginx --with-debug --with-http_ssl_module --with-openssl=/home/hxw/Desktop/TLS-hxw/oqs-provider-hxw-batch/.local --with-cc-opt="-I /home/hxw/Desktop/TLS-hxw/oqs-provider-hxw-batch/.local/include/oqs" --with-ld-opt="-L /home/hxw/Desktop/TLS-hxw/oqs-provider-hxw-batch/.local/lib64" --without-http_gzip_module

sed -i 's/libcrypto.a/libcrypto.a -loqs/g' objs/Makefile;
sed -i 's/EVP_MD_CTX_create/EVP_MD_CTX_new/g; s/EVP_MD_CTX_destroy/EVP_MD_CTX_free/g' src/event/ngx_event_openssl.c;
make && make install;
```

检查nginx安装是否正确，确保安装了正确的openssl

```bash
./nginx -V
nginx version: nginx/1.17.5
built with OpenSSL 3.3.0-dev 
TLS SNI support enabled
configure arguments: --prefix=/home/hxw/Desktop/TLS-hxw/benchmark-platform/nginx-1.17.5/hxw_nginx --with-debug --with-http_ssl_module --with-openssl=/home/hxw/Desktop/TLS-hxw/oqs-provider-hxw-batch/.local --with-cc-opt='-I /home/hxw/Desktop/TLS-hxw/oqs-provider-hxw-batch/.local/include/oqs' --with-ld-opt='-L /home/hxw/Desktop/TLS-hxw/oqs-provider-hxw-batch/.local/lib' --without-http_gzip_module
```


step2:修改测试环境中的路径
step2.1 修改s_timer中的证书路径
```cpp
ret = SSL_CTX_load_verify_locations(ssl_ctx, "/home/hxw/Desktop/TLS-hxw/benchmark-platform/nginx-1.17.5/hxw_nginx/conf/CA.crt", 0); //modify the location of CA
```

step2.2:修改setup.sh中的路径
```bash
OPENSSL=/home/hxw/Desktop/TLS-hxw/oqs-provider-hxw-batch/.local/bin/openssl
OPENSSL_CNF=/home/hxw/Desktop/TLS-hxw/oqs-provider-hxw-batch/scripts/openssl-ca.cnf

NGINX_APP=/home/hxw/Desktop/TLS-hxw/benchmark-platform/nginx-1.17.5/hxw_nginx/sbin/nginx
NGINX_CONF_DIR=/home/hxw/Desktop/TLS-hxw/benchmark-platform/nginx-1.17.5/hxw_nginx/conf

export OPENSSL_PATH=/home/hxw/Desktop/TLS-hxw/oqs-provider-hxw-batch/.local/bin
export PATH=$OPENSSL_PATH:$PATH
export LD_LIBRARY_PATH=/home/hxw/Desktop/TLS-hxw/oqs-provider-hxw-batch/.local/lib
export OPENSSL_APP=/home/hxw/Desktop/TLS-hxw/oqs-provider-hxw-batch/openssl/apps/openssl
export OPENSSL_CONF=/home/hxw/Desktop/TLS-hxw/oqs-provider-hxw-batch/scripts/openssl-ca.cnf
export OPENSSL_MODULES=/home/hxw/Desktop/TLS-hxw/oqs-provider-hxw-batch/_build/lib
export C_INCLUDE_PATH=$C_INCLUDE_PATH:/home/hxw/Desktop/TLS-hxw/oqs-provider-hxw-batch/.local/include

export OPENSSLDIR=/home/hxw/Desktop/TLS-hxw/oqs-provider-hxw-batch/.local/ssl
```

step2.3:修改Makefile中的路径
```bash
OPENSSL_INCLUDE=/home/hxw/Desktop/TLS-hxw/oqs-provider-hxw-batch/.local/include/openssl#$(OPENSSL_DIR)/include
OPENSSL=/home/hxw/Desktop/TLS-hxw/oqs-provider-hxw-batch/.local/bin/openssl#$(OPENSSL_DIR)/apps/openssl

OQS_INCLUDE=/home/hxw/Desktop/TLS-hxw/oqs-provider-hxw-batch/.local/include/oqs#$(OPENSSL_DIR)/oqs/include
OQS_LIB=/home/hxw/Desktop/TLS-hxw/oqs-provider-hxw-batch/.local/lib64 #$(OPENSSL_DIR)/oqs/lib

```

step2.4:修改系统环境变量中指向的openssl.conf文件来修改服务端支持的后量子算法

```bash
[openssl_init]
ssl_conf = ssl_sect

[ssl_sect]
system_default = system_default_sect

[system_default_sect]
Groups = kyber768:kyber1024:ctruprime653
```



