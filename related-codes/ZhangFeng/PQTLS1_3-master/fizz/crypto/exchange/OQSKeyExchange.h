#include <fizz/crypto/exchange/KeyExchange.h>
#include <fizz/crypto/exchange/OQSKeyExchange-inl.h>
#include <oqs/oqs.h>
#include <folly/Range.h>
#include <folly/io/IOBuf.h>
#include <iostream>
#include <cstdlib>
using namespace folly;
namespace fizz
{
template <class T> class OQSKeyExchange : public KeyExchange ///定义了一个类模板但是存在的问题是这里T没有具体的含义，在具体的实现过程中，会将T的类型确定为某个后量子密码算法。
{
public:
	OQSKeyExchange();
	~OQSKeyExchange() override ///析构函数
	{
        	if(isServer && info)
        	{
            		SrvInfo* p = (SrvInfo*)info;
            		delete p;
        	}

        	if(!isServer && info)
        	{
            		CltInfo* p = (CltInfo*)info;
            		delete p;
        	}
			OQS_KEM_free(alg); ///liboqs中的函数
    }
	void generateKeyPair() override;
	std::unique_ptr<folly::IOBuf> getKeyShare() const override;
	std::unique_ptr<folly::IOBuf> generateSharedSecret(folly::ByteRange keyShare) override;

	void setServer(bool is = false) override{isServer = is;}
private:
	typedef struct CltInfo
	{
		std::unique_ptr<uint8_t[]> sk;
		std::unique_ptr<uint8_t[]> pk;
	}CltInfo;
	typedef struct SrvInfo
	{
		std::unique_ptr<uint8_t[]> sendb;
		std::unique_ptr<uint8_t[]> key;
	}SrvInfo;
	OQS_KEM *alg;
	//size_t sk_len, pk_len, ct_len, key_len;
	void* info;
	bool isServer;
};

/*void Print(const unsigned char* p, int len)
{
	int i;
	std::cout<<"*******************************"<<std::ends;
	std::cout<<"*******************************"<<std::endl;
	for(i = 0; i < len; i++)
		std::cout<<std::hex<<(unsigned int)p[i]<<std::ends;
	std::cout<<std::endl;
	std::cout<<"*******************************"<<std::ends;
	std::cout<<"*******************************"<<std::endl;
	std::cout<<std::endl;
	std::cout<<std::endl;
	}*/


/*///
template <class T>: 这是一个类模板的声明或定义的开头。它告诉编译器，接下来的代码中将使用一个模板参数 T
OQSKeyExchange<T>::OQSKeyExchange()： 这是 OQSKeyExchange 类的默认构造函数的实现。OQSKeyExchange<T> 表示该类是一个模板类，其中 T 是模板参数。在默认构造函数的定义中，你可以使用模板参数 T 来声明变量、使用类型 T 的成员
*/

/*后量子算法的类型通过模板参数T来进行标识，进一步地，定义了T::OQS_ID来指示该后量子算法在liboqs中的编号。
接着，在具体的实现过程中，调用liboqs中的函数来实现真正的功能，并将其进行一个封装
*/
template <class T> OQSKeyExchange<T>::OQSKeyExchange()///代表的是默认构造函数的实现。
{
	if(T::OQS_ID >= OQS_KEM_alg_count()) //在related-codes\ZhangFeng\PQTLS1_3-master\fizz\crypto\exchange\OQSKeyExchange-inl.h定义了相关的编号，因此T::OQS_ID是具备实际意义的；OQS_KEM_alg_count() 函数的作用是获取当前 liboqs 库中支持的 OQS（Open Quantum Safe）密钥交换算法的数量。
	{
		throw std::runtime_error("The OQS_ID is error!");
	}

	const char* alg_name = OQS_KEM_alg_identifier(T::OQS_ID);
	if(OQS_KEM_alg_is_enabled(alg_name) != 1)
	{
		throw std::runtime_error("The algorithm is not enabled in liboqs now!");
	}

	alg = OQS_KEM_new(alg_name);
	if(!alg)
	{
		throw std::runtime_error("The algorithm is initilized error in liboqs!");
		
	}
}

template <class T> void OQSKeyExchange<T>::generateKeyPair()
{
	if(isServer == true)
	{
		SrvInfo* p = new SrvInfo();
		p->sendb.reset(new uint8_t[alg->length_ciphertext]);
		p->key.reset(new uint8_t[alg->length_shared_secret]);
		info = (void*)p;
		return;
	}

	CltInfo* p = new CltInfo();
	p->pk.reset(new uint8_t[alg->length_public_key]);
	p->sk.reset(new uint8_t[alg->length_secret_key]);
	OQS_STATUS succ = OQS_KEM_keypair(alg, p->pk.get(), p->sk.get());
	if(succ != OQS_SUCCESS)
	{
		throw std::runtime_error("OQS generate keypairs error!");
	}
	info = (void*)p;
}

template <class T> std::unique_ptr<IOBuf> OQSKeyExchange<T>::getKeyShare() const
{
	if(isServer == true)
	{
		return IOBuf::copyBuffer(((SrvInfo*)info)->sendb.get(), alg->length_ciphertext);
	}

	CltInfo* p = (CltInfo*)info;
	return IOBuf::copyBuffer(p->pk.get(), alg->length_public_key);
}

template <class T> std::unique_ptr<folly::IOBuf> OQSKeyExchange<T>::generateSharedSecret(folly::ByteRange keyShare)
{
	OQS_STATUS succ;
	//std::cout<<"oqs keyshare size:"<<keyShare.size()<<std::endl;
	if(isServer == true)
	{
		SrvInfo* p = (SrvInfo*)info;
		succ = OQS_KEM_encaps(alg, p->sendb.get(), p->key.get(), keyShare.data());
		if(succ != OQS_SUCCESS)
		{
			throw std::runtime_error("OQS encaps error!");
		}
		//std::cout<<"server key:"<<std::endl;
		//Print(p->key, alg->length_shared_secret);
		return IOBuf::copyBuffer(p->key.get(), alg->length_shared_secret);
	}

	std::unique_ptr<uint8_t[]> key(new uint8_t[alg->length_shared_secret]);
	succ = OQS_KEM_decaps(alg, key.get(), keyShare.data(), ((CltInfo*)info)->sk.get());
	if(succ != OQS_SUCCESS)
	{
		throw std::runtime_error("OQS decaps error!");
	}
	//std::cout<<"client key:"<<std::endl;
	//Print(key.get(), 32);
	return IOBuf::copyBuffer(key.get(), alg->length_shared_secret);
}
}
