/*
 * @Author: V4kst1z (dcydane@gmail.com)
 * @Date: 2021-07-23 10:43:24
 * @LastEditors: V4kst1z
 * @Description: encrypt base 实现
 * @FilePath: /lightsocks/src/encrypt/encrypt_base.cpp
 */

#include "encrypt/encrypt_base.h"

EncryptBase::EncryptBase(std::string pw, size_t k_len, size_t i_len)
    : passwd_(pw), key_len_(k_len), iv_len_(i_len) {
  key_ = (char *)malloc(key_len_);
  iv_ = (char *)malloc(iv_len_);
}

void EncryptBase::PrintKey() {
  for (size_t id = 0; id < key_len_; id++) {
    printf("%02x", (unsigned char)key_[id]);
  }
  printf("\n");
}

void EncryptBase::PrintIv() {
  for (size_t id = 0; id < iv_len_; id++) {
    printf("%02x", (unsigned char)iv_[id]);
  }
  printf("\n");
}

EncryptBase::~EncryptBase() {
  free(key_);
  free(iv_);
}

EncryptBaseFactory::MapObj EncryptBaseFactory::mp_ = {};

EncryptBase *EncryptBaseFactory::GetEncryptInstance(std::string encrypt_name,
                                                    std::string passwd,
                                                    size_t k_len,
                                                    size_t i_len) {
  return mp_[encrypt_name](passwd, k_len, i_len);
}
