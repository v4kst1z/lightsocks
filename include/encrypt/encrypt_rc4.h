/*
 * @Author: V4kst1z (dcydane@gmail.com)
 * @Date: 2021-07-23 12:57:12
 * @LastEditors: V4kst1z
 * @Description: rc4-md5 头文件
 * @FilePath: /lightsocks/include/encrypt/encrypt_rc4.h
 */

#ifndef LIGHTSOCKS_INCLUDE_ENCRYPT_ENCRYPT_RC4_H_
#define LIGHTSOCKS_INCLUDE_ENCRYPT_ENCRYPT_RC4_H_

#include "encrypt_base.h"
#include "openssl/rc4.h"

class EncryptBaseRc4 : public EncryptBase {
 public:
  explicit EncryptBaseRc4(std::string, size_t k_len = 16, size_t i_len = 16);

  void SetKey() override;

  void SetIv() override;

  char *GetIvPtr() override;

  char *GetKeyPtr() override;

  void ResetIvAndKey(char *) override;

  void EncryptData(size_t, const unsigned char *, unsigned char *) override;

  void DecryptData(size_t, const unsigned char *, unsigned char *) override;

  ~EncryptBaseRc4() = default;

  DISALLOW_COPY_AND_ASSIGN(EncryptBaseRc4);

 private:
  static EncryptBaseRegister<EncryptBaseRc4> reg;
  RC4_KEY rc4_key_;
};

#endif  // LIGHTSOCKS_INCLUDE_ENCRYPT_ENCRYPT_RC4_H_
