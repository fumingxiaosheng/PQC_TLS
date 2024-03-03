**step1**:在oqs-provider-hxw文件夹下，运行
``` bash
./scripts/fullbuild.sh
```

**step2**:
修改/etc/profile文件
```bash
sudo vim /etc/profile

export OPENSSL_PATH=/home/hxw/exp/oqs-provider-test/oqs-provider-hxw/.local/bin
export PATH=$OPENSSL_PATH:$PATH
export LD_LIBRARY_PATH=/home/hxw/exp/oqs-provider-test/oqs-provider-hxw/.local/lib64
export OPENSSL_APP=/home/hxw/exp/oqs-provider-test/oqs-provider-hxw/openssl/apps/openssl
export OPENSSL_CONF=/home/hxw/exp/oqs-provider-test/oqs-provider-hxw/scripts/openssl-ca.cnf
export OPENSSL_MODULES=/home/hxw/exp/oqs-provider-test/oqs-provider-hxw/_build/lib
export C_INCLUDE_PATH=$C_INCLUDE_PATH:/home/hxw/exp/oqs-provider-test/oqs-provider-hxw/.local/include

export OPENSSLDIR=/home/hxw/exp/oqs-provider-test/oqs-provider-hxw/.local/ssl

source /etc/profile
```

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

