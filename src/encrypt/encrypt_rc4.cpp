/*
 * @Author: V4kst1z (dcydane@gmail.com)
 * @Date: 2021-07-23 12:57:02
 * @LastEditors: V4kst1z
 * @Description: rc4-md5 实现
 * @FilePath: /lightsocks/src/encrypt/encrypt_rc4.cpp
 */

#include "encrypt/encrypt_rc4.h"

#include <cstring>

#include "encrypt/encrypt.h"

EncryptBaseRegister<EncryptBaseRc4> EncryptBaseRc4::reg("rc4-md5");

EncryptBaseRc4::EncryptBaseRc4(std::string pw, size_t k_len, size_t i_len)
    : EncryptBase(pw, k_len, i_len) {
  SetIv();
  SetKey();
}

void EncryptBaseRc4::SetKey() {
  char *key = GetKey(passwd_, key_len_, iv_len_);
  GetRc4Key((unsigned char *)key_, (unsigned char *)key, key_len_,
            (unsigned char *)iv_, iv_len_);
  free(key);
}

void EncryptBaseRc4::SetIv() { SetRandomIv(iv_len_, iv_); }

void EncryptBaseRc4::ResetIvAndKey(char *iv) {
  memcpy(iv_, iv, iv_len_);
  SetKey();
}

void EncryptBaseRc4::EncryptData(size_t len, const unsigned char *indata,
                                 unsigned char *outdata) {
  SetRc4Key(&rc4_key_, key_len_, (unsigned char *)key_);
  Rc4Encrypt(&rc4_key_, len, indata, outdata);
}

void EncryptBaseRc4::DecryptData(size_t len, const unsigned char *indata,
                                 unsigned char *outdata) {
  SetRc4Key(&rc4_key_, key_len_, (unsigned char *)key_);
  Rc4Encrypt(&rc4_key_, len, indata, outdata);
}
