/*
 * @Author: V4kst1z (dcydane@gmail.com)
 * @Date: 2021-07-23 10:43:15
 * @LastEditors: V4kst1z
 * @Description: encrypt base 头文件
 * @FilePath: /lightsocks/include/encrypt/encrypt_base.h
 */

#ifndef LIGHTSOCKS_INCLUDE_ENCRYPT_ENCRYPT_BASE_H_
#define LIGHTSOCKS_INCLUDE_ENCRYPT_ENCRYPT_BASE_H_

#include <unordered_map>

#include "Common.h"

class EncryptBase {
 public:
  explicit EncryptBase(std::string, size_t k_len = 16, size_t i_len = 16);

  virtual void SetKey() {}

  virtual void SetIv() {}

  virtual char *GetIvPtr() { return nullptr; }

  virtual char *GetKeyPtr() { return nullptr; }

  virtual void EncryptData(size_t, const unsigned char *, unsigned char *) {}

  virtual void DecryptData(size_t, const unsigned char *, unsigned char *) {}

  virtual void ResetIvAndKey(char *) {}
  void PrintKey();

  void PrintIv();

  virtual ~EncryptBase();

  DISALLOW_COPY_AND_ASSIGN(EncryptBase);

 protected:
  std::string passwd_;
  size_t key_len_;
  size_t iv_len_;
  char *key_;
  char *iv_;
};

template <typename T>
EncryptBase *CreateEncryptInstance(std::string pw, size_t k_len, size_t i_len) {
  return new T(pw, k_len, i_len);
}

class EncryptBaseFactory {
 public:
  using MapObj =
      std::unordered_map<std::string,
                         EncryptBase *(*)(std::string, size_t, size_t)>;

  EncryptBaseFactory() = default;

  static EncryptBase *GetEncryptInstance(std::string, std::string, size_t,
                                         size_t);

  ~EncryptBaseFactory() = default;

  DISALLOW_COPY_AND_ASSIGN(EncryptBaseFactory);

 protected:
  static MapObj mp_;
};

template <typename T>
class EncryptBaseRegister : public EncryptBaseFactory {
 public:
  EncryptBaseRegister(std::string);

  ~EncryptBaseRegister() = default;

  DISALLOW_COPY_AND_ASSIGN(EncryptBaseRegister);
};

template <typename T>
EncryptBaseRegister<T>::EncryptBaseRegister(std::string encrypt_name) {
  EncryptBaseFactory::mp_.insert({encrypt_name, &CreateEncryptInstance<T>});
}

#endif  // LIGHTSOCKS_INCLUDE_ENCRYPT_ENCRYPT_BASE_H_
