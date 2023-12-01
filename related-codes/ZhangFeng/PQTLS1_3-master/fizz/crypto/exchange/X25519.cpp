/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <fizz/crypto/exchange/X25519.h>

#include <fizz/crypto/Utils.h>

#include <folly/Conv.h>
#include <sodium.h>

///TODO:在这里，对于libsodium库的依赖实现体现在了哪里呢？->依赖一个库，如何来实现相应的代码呢？

using namespace folly;

namespace fizz {

void X25519KeyExchange::generateKeyPair() { ///生成Crve25519的公私钥对
  auto privKey = PrivKey();
  auto pubKey = PubKey();
  static_assert(
      X25519KeyExchange::PrivKey().size() == crypto_scalarmult_SCALARBYTES,
      "Incorrect size of the private key");
  static_assert(
      X25519KeyExchange::PubKey().size() == crypto_scalarmult_BYTES,
      "Incorrect size of the public key");
  auto err = crypto_box_curve25519xsalsa20poly1305_keypair( ///该函数用于生成 Curve25519 密钥对（公钥和私钥）。在这里，它被用于生成 X25519 密钥交换算法中的公钥和私钥。
      pubKey.data(), privKey.data());
  if (err != 0) {
    throw std::runtime_error(to<std::string>("Could not generate keys ", err));
  }
  privKey_ = std::move(privKey);
  pubKey_ = std::move(pubKey);
}

std::unique_ptr<IOBuf> X25519KeyExchange::getKeyShare() const {
  if (!privKey_ || !pubKey_) {
    throw std::runtime_error("Key not generated");
  }
  return IOBuf::copyBuffer(pubKey_->data(), pubKey_->size());
}

std::unique_ptr<folly::IOBuf> X25519KeyExchange::generateSharedSecret(
    folly::ByteRange keyShare){ //fzhang remove const
  if (!privKey_ || !pubKey_) {
    throw std::runtime_error("Key not generated");
  }
  if (keyShare.size() != crypto_scalarmult_BYTES) {
    throw std::runtime_error("Invalid external public key");
  }
  auto key = IOBuf::create(crypto_scalarmult_BYTES);
  key->append(crypto_scalarmult_BYTES);
  int err =
      crypto_scalarmult(key->writableData(), privKey_->data(), keyShare.data());///该函数用于计算 Curve25519 点乘法，生成共享密钥。在这里，它被用于生成 X25519 密钥交换算法中的共享密钥。
  if (err != 0) {
    throw std::runtime_error("Invalid point");
  }
  return key;
}
} // namespace fizz
