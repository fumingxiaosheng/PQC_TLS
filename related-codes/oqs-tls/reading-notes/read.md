代码网址:https://github.com/open-quantum-safe/openssl

open-quantumn-safe网址:https://openquantumsafe.org/ oqs的主要工作路线为开发相关的密码学库和将这些集成到相关的协议中

openssl的官网介绍: https://www.openssl.org/
openssl的provider介绍: csrc.nist.gov/Projects/post-quantum-cryptography/publications

这里似乎是在介绍怎么添加新的加密原语？https://www.openssl.org/docs/manmaster/man7/provider-cipher.html

# 一些官方文档的阅读总结
## 2023-12-18:
openssl的官网感觉一直在介绍怎么去用相应的函数，并没有给出相关的内容
todo:看一下代码文档里的md文件
## 2024-1-7
related-codes\oqs-tls\openssl-master\demos\keyexch\x25519.c主体流程是生成对等方的公钥和私钥，然后以传递参数的形式来模拟了双方交互自己公钥的行为，最终生成一个共享的秘密并比较两个秘密之间是否相等。

在related-codes\oqs-tls\openssl-master\include\openssl\core_names.h.in中，给出了不同的值对应的宏定义，其中，关于KEM的是下面的两条
```cpp
/* OSSL_KEM_PARAM_OPERATION values */
#define OSSL_KEM_PARAM_OPERATION_RSASVE     "RSASVE" 
#define OSSL_KEM_PARAM_OPERATION_DHKEM      "DHKEM"
```
>RSASVE 是 NIST.SP.800-56Br2 中定义的密钥交换机制的一部分，它指的是基于 RSA 的密钥交换算法。具体而言，RSASVE（RSA Key Encapsulation Mechanism with Sender Validation）是 NIST 标准中描述的一种密钥封装机制，用于保护密钥交换的安全性。

related-codes\oqs-tls\openssl-master\include 相关的头文件都定义在这个文件夹下

TODO:
X25519使用的函数都是从哪里来的

## 2024-1-8
下图似乎表示，在oqs中支持的是"X25519", "ED25519", "X448" or "ED448"四种密钥协商的方法
![Alt text](image-1.png)

### EVP_PKEY类型的查找
![Alt text](image-2.png)
evp_pkey_st结构体定义在related-codes\oqs-tls\openssl-master\include\crypto\evp.h中
```cpp
struct evp_pkey_st {
    /* == Legacy attributes == */
    int type;
    int save_type;

# ifndef FIPS_MODULE
    /*
     * Legacy key "origin" is composed of a pointer to an EVP_PKEY_ASN1_METHOD,
     * a pointer to a low level key and possibly a pointer to an engine.
     */
    const EVP_PKEY_ASN1_METHOD *ameth;
    ENGINE *engine;
    ENGINE *pmeth_engine; /* If not NULL public key ENGINE to use */

    /* Union to store the reference to an origin legacy key */
    union legacy_pkey_st pkey;

    /* Union to store the reference to a non-origin legacy key */
    union legacy_pkey_st legacy_cache_pkey;
# endif

    /* == Common attributes == */
    CRYPTO_REF_COUNT references;
    CRYPTO_RWLOCK *lock;
#ifndef FIPS_MODULE
    STACK_OF(X509_ATTRIBUTE) *attributes; /* [ 0 ] */
    int save_parameters;
    unsigned int foreign:1; /* the low-level key is using an engine or an app-method */
    CRYPTO_EX_DATA ex_data;
#endif

    /* == Provider attributes == */

    /*
     * Provider keydata "origin" is composed of a pointer to an EVP_KEYMGMT
     * and a pointer to the provider side key data.  This is never used at
     * the same time as the legacy key data above.
     */
    EVP_KEYMGMT *keymgmt;//密钥管理的方式
    void *keydata;//存储具体的密钥值，具体的存储方式由keymgmt来决定
    /*
     * If any libcrypto code does anything that may modify the keydata
     * contents, this dirty counter must be incremented.
     */
    size_t dirty_cnt;//记录密钥被修改的次数

    /*
     * To support transparent execution of operation in backends other
     * than the "origin" key, we support transparent export/import to
     * those providers, and maintain a cache of the imported keydata,
     * so we don't need to redo the export/import every time we perform
     * the same operation in that same provider.
     */
    STACK_OF(OP_CACHE_ELEM) *operation_cache;//提供cache机制来避免重复的加载

    /*
     * We keep a copy of that "origin"'s dirty count, so we know if the
     * operation cache needs flushing.
     */
    size_t dirty_cnt_copy;

    /* Cache of key object information */
    struct {
        int bits;
        int security_bits;
        int size;
    } cache;
} /* EVP_PKEY */ ;

```
与此类似的，在types.
其具体的结构体在related-codes\oqs-tls\openssl-master\crypto\evp\evp_local.h中进行定义
![Alt text](image-3.png)

### KEX相关的结构体查找
在related-codes\oqs-tls\openssl-master\crypto\evp\evp_local.h文件中，存在结构体evp_keyexch_st(EVP_KEYEXCH)
```cpp
/*2024-1-8
每个成员函数指针都指向一个具体的实现，从而提供了一种灵活的方式，允许不同的密钥交换方法通过实现这些函数来与 OpenSSL 库进行集成。
*/
struct evp_keyexch_st {
    int name_id;
    char *type_name;
    const char *description;
    OSSL_PROVIDER *prov;//表示提供者的信息
    CRYPTO_REF_COUNT refcnt;//引用计数，用于追踪该结构体被引用的次数

    //密钥交换上下文的创建和销毁
    OSSL_FUNC_keyexch_newctx_fn *newctx;
    OSSL_FUNC_keyexch_init_fn *init;
    OSSL_FUNC_keyexch_freectx_fn *freectx;
    OSSL_FUNC_keyexch_dupctx_fn *dupctx;

    OSSL_FUNC_keyexch_set_peer_fn *set_peer; //设置密钥交换的对等方信息
    OSSL_FUNC_keyexch_derive_fn *derive;//执行密钥派生操作

    //上下文参数的设置和获取
    OSSL_FUNC_keyexch_set_ctx_params_fn *set_ctx_params;
    OSSL_FUNC_keyexch_settable_ctx_params_fn *settable_ctx_params;
    OSSL_FUNC_keyexch_get_ctx_params_fn *get_ctx_params;
    OSSL_FUNC_keyexch_gettable_ctx_params_fn *gettable_ctx_params;

} /* EVP_KEYEXCH */;
```
在相关的exch代码的前部分，给出了结构体中相关元素的初始化方法
related-codes\oqs-tls\openssl-master\providers\implementations\exchange\dh_exch.c
related-codes\oqs-tls\openssl-master\providers\implementations\exchange\ecdh_exch.c

![Alt text](image-4.png)
TODO:
dh_exch和ecdh_exch内的各个函数时怎么实现的，以及如何把它传递到KEX相关的结构体中的？
## 2024-1-9
在related-codes\oqs-tls\openssl-master\providers\implementations\include\prov\implementations.h中，存在对于所有的密钥交换算法的总结
``` cpp
extern const OSSL_DISPATCH ossl_dh_keyexch_functions[];
extern const OSSL_DISPATCH ossl_x25519_keyexch_functions[];
extern const OSSL_DISPATCH ossl_x448_keyexch_functions[];
extern const OSSL_DISPATCH ossl_ecdh_keyexch_functions[];
extern const OSSL_DISPATCH ossl_kdf_tls1_prf_keyexch_functions[];
extern const OSSL_DISPATCH ossl_kdf_hkdf_keyexch_functions[];
extern const OSSL_DISPATCH ossl_kdf_scrypt_keyexch_functions[];
```
![Alt text](image-5.png)


在related-codes\oqs-tls\openssl-master\providers\defltprov.c中，有关于keyexch算法的选择
``` cpp
static const OSSL_ALGORITHM deflt_keyexch[] = {
#ifndef OPENSSL_NO_DH
    { PROV_NAMES_DH, "provider=default", ossl_dh_keyexch_functions },
#endif
#ifndef OPENSSL_NO_EC
    { PROV_NAMES_ECDH, "provider=default", ossl_ecdh_keyexch_functions },
# ifndef OPENSSL_NO_ECX
    { PROV_NAMES_X25519, "provider=default", ossl_x25519_keyexch_functions },
    { PROV_NAMES_X448, "provider=default", ossl_x448_keyexch_functions },
# endif
#endif
    { PROV_NAMES_TLS1_PRF, "provider=default", ossl_kdf_tls1_prf_keyexch_functions },
    { PROV_NAMES_HKDF, "provider=default", ossl_kdf_hkdf_keyexch_functions },
    { PROV_NAMES_SCRYPT, "provider=default",
      ossl_kdf_scrypt_keyexch_functions },
    { NULL, NULL, NULL }
};
```
deflt_keyexch会被在同文件下的函数deflt_query使用，而deflt_query函数作为provider向core提供的接口table的一个元素，该table将被作为provider的初始化函数的一部分

在related-codes\oqs-tls\openssl-master\providers\fips\fipsprov.c中，有关于keyexch算法的选择
``` cpp
static const OSSL_ALGORITHM fips_keyexch[] = {
#ifndef OPENSSL_NO_DH
    { PROV_NAMES_DH, FIPS_DEFAULT_PROPERTIES, ossl_dh_keyexch_functions },
#endif
#ifndef OPENSSL_NO_EC
    { PROV_NAMES_ECDH, FIPS_DEFAULT_PROPERTIES, ossl_ecdh_keyexch_functions },
# ifndef OPENSSL_NO_ECX
    { PROV_NAMES_X25519, FIPS_DEFAULT_PROPERTIES, ossl_x25519_keyexch_functions },
    { PROV_NAMES_X448, FIPS_DEFAULT_PROPERTIES, ossl_x448_keyexch_functions },
# endif
#endif
    { PROV_NAMES_TLS1_PRF, FIPS_DEFAULT_PROPERTIES,
      ossl_kdf_tls1_prf_keyexch_functions },
    { PROV_NAMES_HKDF, FIPS_DEFAULT_PROPERTIES, ossl_kdf_hkdf_keyexch_functions },
    { NULL, NULL, NULL }
};

```
上述代码中OSSL_ALGORITHM的具体结构体定义如下所示
``` cpp
def struct ossl_algorithm_st OSSL_ALGORITHM;
struct ossl_algorithm_st {
    const char *algorithm_names;     /* key */
    const char *property_definition; /* key */
    const OSSL_DISPATCH *implementation; //代表了具体的实现，即函数的实例化
    const char *algorithm_description;
};
```
> 阶段总结:总共提供了dh、ecdh、x25519、x448和kdf这几种实现，并在provider中提供了可选择性

以related-codes\oqs-tls\openssl-master\providers\defltprov.c为例来学习一下provider的实现思路:provider中给出了该provider所支持的各种密码套件的具体算法，获取core所支持的函数，并向core提供自己所支持的相关操作

### 以ossl_rsa_asym_kem_functions为例探究kem的具体集成思路
related-codes\oqs-tls\openssl-master\providers\implementations\kem\rsa_kem.c中定义了ossl_rsa_asym_kem_functions
rsa的具体实现在related-codes\oqs-tls\openssl-master\crypto\rsa中，其中对于rsa的测试文件为related-codes\oqs-tls\openssl-master\test\rsa_test.c和related-codes\oqs-tls\openssl-master\test\rsa_mp_test.c

## 2024-1-10
> 阶段总结:从X25519的测试文件出发，发现了EVP_KEYEXCH，然后根据这个结构体定位到了相关exch(例如ecdh_exch.c)的代码实现，从这些方法被调用的角度出发，找到了provider的相关实现，在provider中发现了关于kem的内容，于是开始研究kem是如何进行集成的。

### RSA算法的基本信息
![Alt text](image-6.png)
(openssl中关于RSASVP的介绍网址)[https://www.openssl.org/docs/man3.0/man7/EVP_PKEY-RSA.html]
![Alt text](image-7.png)
[https://www.openssl.org/docs/man3.0/man7/EVP_KEM-RSA.html] 

### rsa_kem.c代码阅读总结
rsa_kem.c位于related-codes\oqs-tls\openssl-master\providers\implementations\kem\rsa_kem.c中。
rsa_kem.c对外(provider)提供了一个接口数组ossl_rsa_asym_kem_functions，里面存放了所有在rsa_kem.c中实现的函数。
在rsa_kem.c中，主要是调用了rsa的底层实现，实现了封装(rsakem_generate)和解封装函数(rsakem_recover)。此外，还实现了对于ras_kem的上下文(ctx)进行操作(例如复制、销毁、初始化等)的各种函数

> 现在想要找rsa用于加密的具体函数，但存在的问题是该函数指针存在于RSA结构体的meth中，而在RSA_public_encrypt的调用过程中，RSA结构体是作为参数传递过来的，那么就要找调用RSA_public_encrypt的函数，即为rsasve_generate，而该函数却又作为rsa_kem.c对外的唯一接口——数组ossl_rsa_asym_kem_functions中的一个元素，因此需要定位ossl_rsa_asym_kem_functions在哪里被调用，此时又回到了provider中

### provider是如何被调用的


## 2024-1-14
包括libssl在内，所有对于libcrypto的调用都是通过EVP的


![Alt text](image-8.png)

### 官方文档阅读之-算法选择
以下为显示地进行算法选择的过程
```cpp
//声明了一个 EVP_CIPHER_CTX 结构体指针 ctx 和一个 EVP_CIPHER 结构体指针 ciph，用于存储加密上下文和加密算法信息。
EVP_CIPHER_CTX *ctx;
EVP_CIPHER *ciph;
//使用 EVP_CIPHER_CTX_new 函数创建一个新的加密上下文对象，并将其地址赋给 ctx 指针。
ctx = EVP_CIPHER_CTX_new();
//使用 EVP_CIPHER_fetch 函数从 osslctx 中获取 AES-128-CBC 算法的信息，并将其赋给 ciph 指针。
ciph = EVP_CIPHER_fetch(osslctx, "aes-128-cbc", NULL);                /* <=== */
//使用 EVP_EncryptInit_ex 函数初始化加密操作。传入加密上下文 ctx、加密算法信息 ciph、密钥 key 和初始化向量 iv。
EVP_EncryptInit_ex(ctx, ciph, NULL, key, iv);
//使用 EVP_EncryptUpdate 函数对输入的明文数据进行加密，并将结果存储在 ciphertext 中。clen 是一个输出参数，表示加密后的数据长度。
EVP_EncryptUpdate(ctx, ciphertext, &clen, plaintext, plen);
//使用 EVP_EncryptFinal_ex 函数结束加密操作。任何剩余的加密数据将被处理，并将结果追加到 ciphertext 的末尾。最后，更新 clen 以包含完整的加密数据长度。
EVP_EncryptFinal_ex(ctx, ciphertext + clen, &clentmp);
clen += clentmp;
//释放资源
EVP_CIPHER_CTX_free(ctx);
EVP_CIPHER_free(ciph); 
```
## 2024-1-15

## openssl design文档阅读结束
>还是有些许的混乱的


## openssl的编码使用
参考的链接 https://www.openssl.org/docs/man3.0/man7/crypto.html
![Alt text](image-9.png)

```cpp
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>

int main(void)
{
    EVP_MD_CTX *ctx = NULL;
    EVP_MD *sha256 = NULL;
    const unsigned char msg[] = {
        0x00, 0x01, 0x02, 0x03
    };
    unsigned int len = 0;
    unsigned char *outdigest = NULL;
    int ret = 1;

    /* Create a context for the digest operation */
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        goto err;

    /*
     * Fetch the SHA256 algorithm implementation for doing the digest. We're
     * using the "default" library context here (first NULL parameter), and
     * we're not supplying any particular search criteria for our SHA256
     * implementation (second NULL parameter). Any SHA256 implementation will
     * do.
     * In a larger application this fetch would just be done once, and could
     * be used for multiple calls to other operations such as EVP_DigestInit_ex().
     */
    sha256 = EVP_MD_fetch(NULL, "SHA256", NULL); //TODO:这里的default library context的含义是什么？
    if (sha256 == NULL)
        goto err;

   /* Initialise the digest operation */
   if (!EVP_DigestInit_ex(ctx, sha256, NULL)) //sha256指向了具体的函数实现方法
       goto err;

    /*
     * Pass the message to be digested. This can be passed in over multiple
     * EVP_DigestUpdate calls if necessary
     */
    if (!EVP_DigestUpdate(ctx, msg, sizeof(msg)))
        goto err;

    /* Allocate the output buffer */
    outdigest = OPENSSL_malloc(EVP_MD_get_size(sha256));
    if (outdigest == NULL)
        goto err;

    /* Now calculate the digest itself */
    if (!EVP_DigestFinal_ex(ctx, outdigest, &len))
        goto err;

    /* Print out the digest result */
    BIO_dump_fp(stdout, outdigest, len);

    ret = 0;

 err:
    /* Clean up all the resources we allocated */
    OPENSSL_free(outdigest);
    EVP_MD_free(sha256);
    EVP_MD_CTX_free(ctx);
    if (ret != 0)
       ERR_print_errors_fp(stderr);
    return ret;
}
```
## 2024-1-16
在编译过程中，遇到了诸如下述的问题，即目标动态库不存在，经过分析，认定为代码中使用的函数版本和实际上链接到的openssl库的版本不匹配。
![Alt text](a70032cfc74c70fdd28668aaf8828b4.png)
因此，使用下述命令对上述代码进行编译
```
gcc first-test.c -o first-test -lssl -lcrypto -L /usr/local/openssl/lib64
```
注意:在这里需要指明动态链接库的位置-L，使用-lssl代表需要使用的库为libssl和libcrypto(据gpt这里应该使用的是动态链接库)

## 2024-1-18
### A 查找liboqs和openssl之间的链接关系
#### A.a liboqs官方文档的阅读
1.关于生成的静态链接库liboqs的使用
https://github.com/open-quantum-safe/liboqs/wiki/Minimal-example-of-a-post-quantum-KEM
使用下面的命令进行编译
```bash
gcc -Ibuild/include -I/usr/local/openssl/include  -Lbuild/lib -L/usr/local/openssl/lib64 tests/example_kem.c -o example_kem -loqs -lcrypto -pthread
```
需要得到openssl中的lcrypto支持

2.编程的convention
https://github.com/open-quantum-safe/liboqs/wiki/Coding-conventions
公共函数是以大写字母开头的，格式为OQS_KEM_...或者OQS_SIG_...
私有函数(在整个项目中具有全局的范围)不能被生成的lib调用，使用小写字母开头
涉及存储秘密的内存，一旦不使用，应该立即清空，在栈上使用OQS_MEM_cleanse来进行清除，在堆上使用OQS_MEM_secure_free进行清除
使用OQS_STATUS来进行来表示函数是成功还是失败，位于src/common/common.h
使用doxygen来生成代码文档

3.发布notes
https://github.com/open-quantum-safe/liboqs/wiki/Release-process

> A.a完成
#### A.b liboqs-main的代码结构
C:\Users\Lenovo\Desktop\file cache\liboqs-main\tests 存储的是待测试的文件
C:\Users\Lenovo\Desktop\file cache\liboqs-main\src 存储了相关的后量子密码的实现源码，包括sig和kem

#### A.c oqs-provider官方文档的阅读
https://github.com/open-quantum-safe/oqs-provider

STATUS:KEM被集成到了openssl provider中,QSC签名和CMS和SMP被集成到了EVP中,通过编码/解码机制和X.509数据结构提供密钥持久性。
    [Standards supported when deploying oqsprovider](https://github.com/open-quantum-safe/oqs-provider/blob/main/STANDARDS.md):oqs-provider集成到了openssl中，当应用程序调用后量子密码算法时，oqs-provider提供相关的支持。oqs-provider的具体内容依赖于liboqs。
    [oqs-provider中支持的kem的具体信息](https://github.com/open-quantum-safe/oqs-provider/blob/main/oqs-template/oqs-kem-info.md)

ALGORITHMS：
    可以更改下述文件[Configuring oqsprovider](https://github.com/open-quantum-safe/oqs-provider/blob/main/CONFIGURE.md#pre-build-configuration)来更改TLS中对于不同密码算法的支持。
    对于后量子密码算法，不仅仅只有单独模式，还有和一般的密码算法的混合模式，例如以p256_开头的。
    **在增加了新的密码算法时，需要调整OID和相关的算法实现**

Quick Start:
    运行scripts/fullbuild.sh和scripts/runtests.sh
    



##### A.a.a 查看openssl支持的相关算法

可以使用下述命令来查看oqsprovider支持的kem算法类型
```bash
openssl list -signature-algorithms -provider oqsprovider and openssl list -kem-algorithms -provider oqsprovider
```
> TODO:应该如何进行集成呢？

```bash
hxw@ubuntu:~/Desktop/liboqs-main$ openssl list -provider default -kem-algorithms
  { 1.2.840.113549.1.1.1, 2.5.8.1.1, RSA, rsaEncryption } @ default
  { 1.2.840.10045.2.1, EC, id-ecPublicKey } @ default
  { 1.3.101.110, X25519 } @ default
  { 1.3.101.111, X448 } @ default
hxw@ubuntu:~/Desktop/liboqs-main$ openssl list -providers
Providers:
  default
    name: OpenSSL Default Provider
    version: 3.2.0
    status: active
hxw@ubuntu:~/Desktop/liboqs-main$ 
```
## 2024-1-20
### A.d oqs-provider的安装
解决找不到liboqs的问题
```bash
hxw@ubuntu:~/Desktop/oqs-provider-main/scripts$ ./fullbuild.sh
need to re-build static liboqs...
cloning liboqs main...
./fullbuild.sh: line 77: git: command not found
liboqs clone failure for branch main. Exiting.
hxw@ubuntu:~/Desktop/oqs-provider-main/scripts$ export liboqs_DIR=/home/hxw/Desktop/liboqs-main/build/lib
```

解决
```bash
hxw@ubuntu:~/Desktop/oqs-provider-main$ ./scripts/fullbuild.sh 
oqsprovider (_build/lib/oqsprovider.so) not built: Building...
CMake Deprecation Warning at CMakeLists.txt:4 (cmake_minimum_required):
  Compatibility with CMake < 3.5 will be removed from a future version of
  CMake.

  Update the VERSION argument <min> value or use a ...<max> suffix to tell
  CMake that the project does not need compatibility with older versions.


-- The C compiler identification is GNU 9.4.0
-- Detecting C compiler ABI info
-- Detecting C compiler ABI info - done
-- Check for working C compiler: /usr/bin/cc - skipped
-- Detecting C compile features
-- Detecting C compile features - done
-- Creating Release build
-- Build will store public keys in PKCS#8 structures
-- Build will not include external encoding library for SPKI/PKCS#8
CMake Error at /usr/local/share/cmake-3.27/Modules/FindPackageHandleStandardArgs.cmake:230 (message):
  Could NOT find OpenSSL, try to set the path to OpenSSL root folder in the
  system variable OPENSSL_ROOT_DIR: Found unsuitable version "1.1.1f", but
  required is at least "3.0" (found /usr/lib/x86_64-linux-gnu/libcrypto.so, )
Call Stack (most recent call first):
  /usr/local/share/cmake-3.27/Modules/FindPackageHandleStandardArgs.cmake:598 (_FPHSA_FAILURE_MESSAGE)
  /usr/local/share/cmake-3.27/Modules/FindOpenSSL.cmake:668 (find_package_handle_standard_args)
  CMakeLists.txt:58 (find_package)


-- Configuring incomplete, errors occurred!
provider build failed. Exiting.
hxw@ubuntu:~/Desktop/oqs-provider-main$ export OPENSSL_ROOT_DIR=/usr/local/openssl
hxw@ubuntu:~/Desktop/oqs-provider-main$ ./scripts/fullbuild.sh 
oqsprovider (_build/lib/oqsprovider.so) not built: Building...
CMake Deprecation Warning at CMakeLists.txt:4 (cmake_minimum_required):
  Compatibility with CMake < 3.5 will be removed from a future version of
  CMake.

  Update the VERSION argument <min> value or use a ...<max> suffix to tell
  CMake that the project does not need compatibility with older versions.


-- Creating Release build
-- Build will store public keys in PKCS#8 structures
-- Build will not include external encoding library for SPKI/PKCS#8
CMake Error at /usr/local/share/cmake-3.27/Modules/FindPackageHandleStandardArgs.cmake:230 (message):
  Could NOT find OpenSSL, try to set the path to OpenSSL root folder in the
  system variable OPENSSL_ROOT_DIR: Found unsuitable version "1.1.1f", but
  required is at least "3.0" (found /usr/lib/x86_64-linux-gnu/libcrypto.so, )
Call Stack (most recent call first):
  /usr/local/share/cmake-3.27/Modules/FindPackageHandleStandardArgs.cmake:598 (_FPHSA_FAILURE_MESSAGE)
  /usr/local/share/cmake-3.27/Modules/FindOpenSSL.cmake:668 (find_package_handle_standard_args)
  CMakeLists.txt:58 (find_package)


-- Configuring incomplete, errors occurred!
provider build failed. Exiting.
```
在环境变量中关于openssl的部分都是正确的
![Alt text](image-10.png)

于是把/usr/lib/x86_64-linux-gnu/给删除了

```bash
hxw@ubuntu:~/Desktop/oqs-provider-main$ ./scripts/fullbuild.sh 



/usr/local/openssl/lib64

/home/hxw/Desktop/liboqs-main/build/lib
/usr/local/openssl/lib64
oqsprovider (_build/lib/oqsprovider.so) not built: Building...
openssl install type
cmake: error while loading shared libraries: libcrypto.so.1.1: cannot open shared object file: No such file or directory
before cmake
cmake: error while loading shared libraries: libcrypto.so.1.1: cannot open shared object file: No such file or directory
provider build failed. Exiting.
```

**打算在不安装openssl3.x和liboqs的情况下直接进行安装**
会将openssl和liboqs下载在当前文件夹下

Found OpenSSL: /home/hxw/Desktop/oqs-provider-main/.local/lib/libcrypto.so (found suitable version "3.3.0", minimum required is "3.0")  
-- liboqs found: Include dir at /home/hxw/Desktop/oqs-provider-main/.local/include;/home/hxw/Desktop/oqs-provider-main/.local/include/oqs

最终的安装命令行输出如下所示:
```bash
oqsprovider (_build/lib/oqsprovider.so) not built: Building...
openssl install type
CMake Deprecation Warning at CMakeLists.txt:4 (cmake_minimum_required):
  Compatibility with CMake < 3.5 will be removed from a future version of
  CMake.

  Update the VERSION argument <min> value or use a ...<max> suffix to tell
  CMake that the project does not need compatibility with older versions.


-- The C compiler identification is GNU 9.4.0
-- Detecting C compiler ABI info
-- Detecting C compiler ABI info - done
-- Check for working C compiler: /usr/bin/cc - skipped
-- Detecting C compile features
-- Detecting C compile features - done
-- Creating Release build
-- Build will store public keys in PKCS#8 structures
-- Build will not include external encoding library for SPKI/PKCS#8
-- Found OpenSSL: /home/hxw/Desktop/oqs-provider-main/.local/lib/libcrypto.so (found suitable version "3.3.0", minimum required is "3.0")  
-- liboqs found: Include dir at /home/hxw/Desktop/oqs-provider-main/.local/include;/home/hxw/Desktop/oqs-provider-main/.local/include/oqs
fatal: not a git repository (or any of the parent directories): .git
-- Building commit  in /home/hxw/Desktop/oqs-provider-main
-- Configuring done (1.4s)
-- Generating done (0.1s)
-- Build files have been written to: /home/hxw/Desktop/oqs-provider-main/_build
before cmake
[  3%] Building C object oqsprov/CMakeFiles/oqsprovider.dir/oqsprov.c.o
[  7%] Building C object oqsprov/CMakeFiles/oqsprovider.dir/oqsprov_capabilities.c.o
[ 10%] Building C object oqsprov/CMakeFiles/oqsprovider.dir/oqsprov_keys.c.o
[ 14%] Building C object oqsprov/CMakeFiles/oqsprovider.dir/oqs_kmgmt.c.o
[ 17%] Building C object oqsprov/CMakeFiles/oqsprovider.dir/oqs_sig.c.o
[ 21%] Building C object oqsprov/CMakeFiles/oqsprovider.dir/oqs_kem.c.o
[ 25%] Building C object oqsprov/CMakeFiles/oqsprovider.dir/oqs_encode_key2any.c.o
[ 28%] Building C object oqsprov/CMakeFiles/oqsprovider.dir/oqs_endecoder_common.c.o
[ 32%] Building C object oqsprov/CMakeFiles/oqsprovider.dir/oqs_decode_der2key.c.o
[ 35%] Building C object oqsprov/CMakeFiles/oqsprovider.dir/oqsprov_bio.c.o
[ 39%] Linking C shared module ../lib/oqsprovider.so
[ 39%] Built target oqsprovider
[ 42%] Building C object test/CMakeFiles/oqs_test_signatures.dir/oqs_test_signatures.c.o
[ 46%] Building C object test/CMakeFiles/oqs_test_signatures.dir/test_common.c.o
[ 50%] Linking C executable oqs_test_signatures
[ 50%] Built target oqs_test_signatures
[ 53%] Building C object test/CMakeFiles/oqs_test_kems.dir/oqs_test_kems.c.o
[ 57%] Building C object test/CMakeFiles/oqs_test_kems.dir/test_common.c.o
[ 60%] Linking C executable oqs_test_kems
[ 60%] Built target oqs_test_kems
[ 64%] Building C object test/CMakeFiles/oqs_test_groups.dir/oqs_test_groups.c.o
[ 67%] Building C object test/CMakeFiles/oqs_test_groups.dir/test_common.c.o
[ 71%] Building C object test/CMakeFiles/oqs_test_groups.dir/tlstest_helpers.c.o
[ 75%] Linking C executable oqs_test_groups
[ 75%] Built target oqs_test_groups
[ 78%] Building C object test/CMakeFiles/oqs_test_tlssig.dir/oqs_test_tlssig.c.o
[ 82%] Building C object test/CMakeFiles/oqs_test_tlssig.dir/test_common.c.o
[ 85%] Building C object test/CMakeFiles/oqs_test_tlssig.dir/tlstest_helpers.c.o
[ 89%] Linking C executable oqs_test_tlssig
[ 89%] Built target oqs_test_tlssig
[ 92%] Building C object test/CMakeFiles/oqs_test_endecode.dir/oqs_test_endecode.c.o
[ 96%] Building C object test/CMakeFiles/oqs_test_endecode.dir/test_common.c.o
[100%] Linking C executable oqs_test_endecode
[100%] Built target oqs_test_endecode

```

接着，[配置openssl3到系统环境变量](https://zhuanlan.zhihu.com/p/662481058)中
在/etc/profile中添加如下内容，并使得配置生效
```bash
export OPENSSL_PATH=/home/hxw/Desktop/oqs-provider-main/.local/bin
export PATH=$OPENSSL_PATH:$PATH
``` 
```bash
hxw@ubuntu:~$ sudo gedit /etc/profile

(gedit:2136): Tepl-WARNING **: 22:24:48.563: GVfs metadata is not supported. Fallback to TeplMetadataManager. Either GVfs is not correctly installed or GVfs metadata are not supported on this platform. In the latter case, you should configure Tepl with --disable-gvfs-metadata.
hxw@ubuntu:~$ source /etc/profile
hxw@ubuntu:~$ printenv PATH | grep openssl
hxw@ubuntu:~$ printenv PATH | grep local
/home/hxw/Desktop/oqs-provider-main/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
hxw@ubuntu:~$ openssl version
OpenSSL 3.3.0-dev  (Library: OpenSSL 3.3.0-dev )

```
![Alt text](image-11.png)

最终，生成的oqsprovider.so的路径为/home/hxw/Desktop/oqs-provider-main/_build/lib

***下面需要将oqsprovider注册到openssl系统中***
使用下述命令之后，可以不用再指定-provider的路径了
``` bash
export OPENSSL_MODULES=/home/hxw/Desktop/oqs-provider-main/_build/lib
```

``` bash
hxw@ubuntu:~/Desktop/oqs-provider-main/.local/lib64/ossl-modules$ openssl list -providers
Providers:
  default
    name: OpenSSL Default Provider
    version: 3.3.0
    status: active
hxw@ubuntu:~/Desktop/oqs-provider-main/.local/lib64/ossl-modules$ cp /home/hxw/Desktop/oqs-provider-main/_build/lib/oqsprovider.so /home/hxw/Desktop/oqs-provider-main/.local/lib64/ossl-modules/oqsprovider.so
hxw@ubuntu:~/Desktop/oqs-provider-main/.local/lib64/ossl-modules$ ls -l
total 4700
-rwxr-xr-x 1 hxw hxw  171368 Jan 20 19:28 legacy.so
-rwxrwxr-x 1 hxw hxw 4640320 Jan 21 05:26 oqsprovider.so
```

在调用oqs-provider中集成的测试脚本时，能够正确地输出相关的信息
``` bash
hxw@ubuntu:~/Desktop/oqs-provider-main$ ./scripts/runtests.sh 
Test setup:
LD_LIBRARY_PATH=/home/hxw/Desktop/oqs-provider-main/.local/lib64
OPENSSL_APP=/home/hxw/Desktop/oqs-provider-main/openssl/apps/openssl
OPENSSL_CONF=/home/hxw/Desktop/oqs-provider-main/scripts/openssl-ca.cnf
OPENSSL_MODULES=/home/hxw/Desktop/oqs-provider-main/_build/lib
No OQS-OpenSSL111 interop test because of absence of docker
Version information:
OpenSSL 3.3.0-dev  (Library: OpenSSL 3.3.0-dev )
Providers:
  default
    name: OpenSSL Default Provider
    version: 3.3.0
    status: active
    build info: 3.3.0-dev
    gettable provider parameters:
      name: pointer to a UTF8 encoded string (arbitrary size)
      version: pointer to a UTF8 encoded string (arbitrary size)
      buildinfo: pointer to a UTF8 encoded string (arbitrary size)
      status: integer (arbitrary size)
  oqsprovider
    name: OpenSSL OQS Provider
    version: 0.5.3-dev
    status: active
    build info: OQS Provider v.0.5.3-dev () based on liboqs v.0.10.0-dev
    gettable provider parameters:
      name: pointer to a UTF8 encoded string (arbitrary size)
      version: pointer to a UTF8 encoded string (arbitrary size)
      buildinfo: pointer to a UTF8 encoded string (arbitrary size)
      status: integer (arbitrary size)
Cert gen/verify, CMS sign/verify, CA tests for all enabled OQS signature algorithms commencing: 
.......................
External interop tests commencing
 Cloudflare:
kex=X25519Kyber768Draft00
kex=X25519Kyber512Draft00
Test project /home/hxw/Desktop/oqs-provider-main/_build
    Start 1: oqs_signatures
1/5 Test #1: oqs_signatures ...................   Passed   11.13 sec
    Start 2: oqs_kems
2/5 Test #2: oqs_kems .........................   Passed    1.54 sec
    Start 3: oqs_groups
3/5 Test #3: oqs_groups .......................   Passed    1.81 sec
    Start 4: oqs_tlssig
4/5 Test #4: oqs_tlssig .......................   Passed    8.74 sec
    Start 5: oqs_endecode
5/5 Test #5: oqs_endecode .....................   Passed   20.08 sec

100% tests passed, 0 tests failed out of 5

Total Test time (real) =  43.35 sec

All oqsprovider tests passed.
 
```

```bash
hxw@ubuntu:~/Desktop/oqs-provider-main/.local/ssl$ sudo gedit openssl.cnf

(gedit:4308): Tepl-WARNING **: 05:52:46.126: GVfs metadata is not supported. Fallback to TeplMetadataManager. Either GVfs is not correctly installed or GVfs metadata are not supported on this platform. In the latter case, you should configure Tepl with --disable-gvfs-metadata.


hxw@ubuntu:~/Desktop/oqs-provider-main/.local/ssl$ sudo gedit /etc/ssl/openssl.cnf 

(gedit:4331): Tepl-WARNING **: 05:54:14.348: GVfs metadata is not supported. Fallback to TeplMetadataManager. Either GVfs is not correctly installed or GVfs metadata are not supported on this platform. In the latter case, you should configure Tepl with --disable-gvfs-metadata.

hxw@ubuntu:~/Desktop/oqs-provider-main/.local/ssl$ sudo gedit /home/hxw/Desktop/oqs-provider-main/openssl/apps/openssl.cnf

(gedit:4394): Tepl-WARNING **: 05:58:03.725: GVfs metadata is not supported. Fallback to TeplMetadataManager. Either GVfs is not correctly installed or GVfs metadata are not supported on this platform. In the latter case, you should configure Tepl with --disable-gvfs-metadata.

```

将下述环境变量写到/etc/profile中，便能将oqsprovider添加到openssl的provider列表中
```bash
hxw@ubuntu:~$ export LD_LIBRARY_PATH=/home/hxw/Desktop/oqs-provider-main/.local/lib64
hxw@ubuntu:~$ export OPENSSL_APP=/home/hxw/Desktop/oqs-provider-main/openssl/apps/openssl
hxw@ubuntu:~$ export OPENSSL_CONF=/home/hxw/Desktop/oqs-provider-main/scripts/openssl-ca.cnf
hxw@ubuntu:~$ export OPENSSL_MODULES=/home/hxw/Desktop/oqs-provider-main/_build/lib
```

> openssl version -d可以用来查看相关的路径配置

### A.e oqs-provider的使用
[官方文档的使用教程](https://github.com/open-quantum-safe/oqs-provider/blob/main/USAGE.md#running-a-client-to-interact-with-quantum-safe-kem-algorithms)
主要包括一些命令的配置等等

#### A.e.a 显示使用命令行进行调用
使用下述命令查看oqsprovider中提供的签名算法
```bash
openssl list -signature-algorithms -provider-path /home/hxw/Desktop/oqs-provider-main/_build/lib -provider oqsprovider
openssl list -kem-algorithms -provider-path /home/hxw/Desktop/oqs-provider-main/_build/lib -provider oqsprovider
```
#### A.e.b C API

#### A.e.c 系统文件


### A.f openssl中openssl s_server和s_client的连接
[oqs-openssl1.1.1中running](https://github.com/open-quantum-safe/openssl?tab=readme-ov-file)
首先生成一个CA的根证书，然后服务端生成自己的密钥对并让CA签名。客户端选定KEX的方式和服务端交互

生成签名文件
```
openssl req -x509 -new -newkey dilithium3 -keyout dilithium3_CA.key -out dilithium3_CA.crt -nodes -subj "/CN=test CA" -days 365 -config ~/Desktop/oqs-provider-main/openssl/apps/openssl.cnf -provider-path /home/hxw/Desktop/oqs-provider-main/_build/lib -provider oqsprovider
```

### A.g 使用openssl进行集成的例子
https://github.com/open-quantum-safe/oqs-demos
包括httpd、wireshark等

### A.h oqs-provider 将liboqs接入到openssl的接口代码阅读
根据一般的provider的编写规范，一般都会写一个新的provider_init函数，观察下面的截图，可以得出结论，oqs-provider也是以provider的形式接入的
![Alt text](image-12.png)

### 
# openssl
## 代码结构
demos下给出了一些样例->看下能不能跑起来


related-codes\oqs-tls\openssl-master\crypto\evp\kem.c 似乎给出了kem的接口

想尝试写一个代码，但是发现无法打开openssl
![Alt text](image.png)
>如果说自己要内置一个库来进行实现的话，可能需要在装openssl的时候就使用源码安装的方式，然后再进行库的一个调用

## 概述
1.命令行
2.两个库libssl(提供两个实体之间的ssl交互)和libcrypto(提供相关的密码学原语，例如加解密等)
3.大量provider

openssl的多线程安全问题和需要去关注调用的openssl函数的返回值所代表的确切的含义并进行错误的处理
openssl在第一次时会加载一个配置文件
## provider
在openssl中，provider是提供相应密码套件原语的部分。
provider允许用户动态地加载和选择密码学实现

> In order to use an algorithm you must have at least one provider loaded that contains an implementation of it.
内置(built-in)的provider可能已经在libcrypto中实现或者由函数本身实现
还有一类provider是一个单独的可加载模块文件，例如.so和.dll

provider一般只会load和unload一次
>是对应了prov函数中的init函数吗？

不同的provider可能会实现一个相同的算法，使用PROPERTY QUERY STRINGS来为算法的选择指定一些条件，例如provider=default

每个provider下都会有相应的算法实现，应该进行选择

### 1.default provider
默认提供程序是作为libcrypto库的一部分内置的，包含所有最常用的算法实现。
### 2.base provider
基本提供程序是作为libcrypto库的一部分内置的，包含用于编码和解码OpenSSL密钥的算法实现。一些不是fips的算法支持fips mode的使用
provider=base
### 3.fips provider
FIPS提供程序是一个可动态加载的模块，因此必须以代码或通过OpenSSL配置显式加载。包含所有通过fips标准的算法
provider=fips

### 4.Legacy provider
遗留提供程序是一个可动态加载的模块，因此必须以代码或通过OpenSSL配置显式加载（请参阅配置（5））。它包含被认为不安全的或不再常用的算法实现，如MD2或RC4。
provider=legacy

### 5.null provider
null提供程序是作为libcrypto库的一部分内置的。它根本不包含任何算法。
具体来说，在代码中的related-codes\oqs-tls\openssl-master\providers文件夹下
有baseprov.c、defltprov.c、legacyprov.c、nullprov.c和fips\fipsprov.c这5种文件

## library context
库的语境规定了一些配置
每一个provider都会使用一个library context作为参数
library context都会使用OSSL_LIB_CTX作为参数，默认值为NULL，代表使用default library context

## libcrypto
libcrypto适用于ssl的实现
>The functionality includes symmetric encryption, public key cryptography, key agreement, certificate handling, cryptographic hash functions, cryptographic pseudo-random number generators, message authentication codes (MACs), key derivation functions (KDFs), and various utilities.

在openssl中，算法(algorithm)代表的是一整个提出的算法（比如说sha256、AES加密等等），不同的provider下可能实现了不同的算法，比如说default和fips下对于RSA都有实现，但是一个是通过了fips测试的。

使用显示的fetch的方法来寻找匹配的算法，使用APINAME_fetch来找对应的算法，使用完成后使用APINAME_free来释放掉相应的指针。APINAME_fetch函数需要指定library context(只有在该context下的provider中的algorithm才能被使用)

使用隐式的方法来寻找匹配的算法，主要是为了和以前不支持显示寻找的版本进行兼容，使用了默认的搜索标准

在opensll中，操作(operation)代表的是每个不同的算法所执行的操作，比如说加密等等

对于相应libcrypto中获取的算法的使用，需要借助EVP(https://www.openssl.org/docs/manmaster/man7/evp.html)这个API。具体的使用流程为：（1）首先创建一个CTX，例如EVP_CIPHER_CTX（2）使用init函数来进行初始化 （3）使用update的方式来给出数据 （4）final call进行调用并得到最终的输出结果

关于**openssl**中密钥封装的产生与使用方式，可以直接再新[产生](https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_Q_keygen.html)一个，也可以从别的地方load过来，后者便涉及到了[encode](https://www.openssl.org/docs/manmaster/man3/OSSL_ENCODER_CTX_new_for_pkey.html)和[Decode](https://www.openssl.org/docs/manmaster/man3/OSSL_DECODER_CTX_new_for_pkey.html)的问题


## libssl
libssl提供了一些安全网络交互协议的具体实现(比如说SSL/TLS、DTLS、QUIC等)，基于libcrypto来实现相关的协议中所使用到的密码原语。

为了使用libssl，首先必须使用头文件<openssl/ssl.h>，主要使用到的两个数据结构是SSL和SSL_CTX

数据结构SSL再不同的互联网交互协议中有不同的含义，例如SSL/TLS和QUIC中是stream(要求必须按序且没有数据丢失,stream可以是单向的，也可以是双向的),在DTLS中是datagram(允许丢失且不一定是按序到达的)

数据结构SSL_CTX对象用于为基础连接创建SSL对象。基于一个SSL_CTX对象可以创建多个SSL对象(连接)。对于SSL_CTX的修改会被反应到基于其的SSL对象上，而基于同一个SSL_CTX的SSL对象之间是不会互相影响的。

## openssl中的ssl协议简介
一些用语:
endpoint代表的是通信的双方
peer代表的是当前语境下通信一方的对方

ssl协议的历史:
1995年:SSLv2
1996年:SSLv3
1999年:TLSv1.0
2006年:TLSv1.1
2008年:TLSv1.2
2018年:TLSv1.3
openssl支持SSLv3及以上的版本，需要注意的是，对于SSLv3的支持是使用的编译时选项

一些重要的点:
TLS支持TLS版本的协商，使用的是客户端和服务端所共同支持的最大的版本号

认证:
需要使用到X.509证书，证书中包含了服务端的一些信息，比如说DNS主机名、公钥。认证的过程使用了签名同时还使用到了CA来完成整个证书链的认证。由于需要对整个证书链进行认证，对于证书链上的CA，认证方应该具备其证书，这就要求endpoint有这些证书的本地存储。
可以使用openssl version -d来查看当前openssl中是否自带了一些链上的证书文件，通常证书文件会被放在cert文件夹下。此外，SSL_CERT_PATH是openssl查找相应证书文件的系统环境变量

比较重要的几个数据结构:
1.SSL在TLS连接中，SSL结构体用于双方数据的存储与传输，endpoint可以向其中写入数据，也可以向其中读出数据。一个新的SSL结构体是从SSL_CTX中获取得到的，在SSL_CTX中做一些配置，然后从该SSL_CTX中生成多个SSL结构体(SSL结构体会继承SSL_CTX中的配置)。
2.SSL对象会和两个BIO对象相关联。BIO对象用于从下面的传输层发送或者接收数据。BIO充当的是TCP套接字的功能，具体是充当一方还是两方的套接字，这是由编程者决定的。

会话(session)中保存了客户端和服务端之间的一系列TLS参数，可以在下次连接时重新使用这些参数。

## TLS的连接阶段
[参考链接](https://www.openssl.org/docs/manmaster/man7/ossl-guide-tls-introduction.html)
setup:
1.双方创建SSL_CTX对象并且配置它
2.客户端创建SSL对象来代表新的TLS连接。应用相关的配置并使用BIO对象来创建TCP套接字。
3.服务端创建一个套接字来监听所有的客户端发起的连接。一旦建立了一个连接，服务端也会创建一个SSL对象，并将其和一个BIO对象相关联。

handshake:
双方交换信息，ClientHello和ServerHello。整个handshake的过程是以"Finished"消息来作为终结的。

data transfer phase:
客户端和服务端任意地写/读数据

shutdown:
"close_notify"用于标记连接的关闭
hh