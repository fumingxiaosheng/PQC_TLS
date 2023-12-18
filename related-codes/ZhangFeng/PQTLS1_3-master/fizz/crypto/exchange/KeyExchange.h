/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/Range.h>
#include <folly/io/IOBuf.h>

///和最初的fizz-main相比，少了clone和getExpectedKeyShareSize这两个函数
namespace fizz {

/**
 * Interface for key exchange algorithms.
 */
class KeyExchange {///由于其中的虚函数没有被实例化，因此KeyExchange是一个抽象类，不能被直接实例化，需要通过派生类被实例化
 public:
  virtual ~KeyExchange() = default; ///析构函数

  virtual void setServer(bool is = false){} //fzhang
  /**
   * Generates an ephemeral key pair.
   */
  virtual void generateKeyPair() = 0; ///用于生成临时的密钥对

  /**
   * Returns the public key to share with peers.
   *
   * generateKeyPair() must be called before.
   */
  virtual std::unique_ptr<folly::IOBuf> getKeyShare() const = 0; ///用于发送自己的公钥

  /**
   * Generate a shared secret with our key pair and a peer's public key share.
   *
   * Performs all necessary validation of the public key share and throws on
   * error.
   *
   * generateKeyPair() must be called before.
   */
  virtual std::unique_ptr<folly::IOBuf> generateSharedSecret( ///计算最终的共享密钥
      folly::ByteRange keyShare) = 0; //fzhang remove const
};
} // namespace fizz
