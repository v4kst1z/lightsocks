/*
 * @Author: V4kst1z (dcydane@gmail.com)
 * @Date: 2021-07-23 10:41:12
 * @LastEditors: V4kst1z
 * @Description: openssl wrapper 实现
 * @FilePath: /lightsocks/src/encrypt/encrypt.cpp
 */

#include "encrypt/encrypt.h"

#include <cstring>
#include <random>

#include "openssl/md5.h"

char *GetKey(std::string &passwd, size_t key_len, size_t iv_len) {
  size_t id = 0;
  char *key = (char *)malloc(key_len + iv_len);
  char *data = (char *)malloc(passwd.size() + MD5_DIGEST_LENGTH);
  unsigned char res[MD5_DIGEST_LENGTH];

  memset(key, '\x00', key_len + iv_len);
  memset(data, '\x00', passwd.size() + MD5_DIGEST_LENGTH);
  while (id * 16 < (key_len + iv_len)) {
    if (id > 0) {
      memcpy(data, key + (id - 1) * MD5_DIGEST_LENGTH, MD5_DIGEST_LENGTH);
      memcpy(data + MD5_DIGEST_LENGTH, passwd.data(), passwd.size());
      MD5((unsigned char *)data, passwd.size() + MD5_DIGEST_LENGTH, res);
      memcpy(key + id * MD5_DIGEST_LENGTH, res, MD5_DIGEST_LENGTH);
    } else {
      memcpy(data, passwd.data(), passwd.size());
      MD5((unsigned char *)data, passwd.size(), res);
      memcpy(key, res, MD5_DIGEST_LENGTH);
    }
    id++;
  }
  free(data);
  return key;
}

void PrintMd5(unsigned char *md5) {
  for (size_t i = 0; i < MD5_DIGEST_LENGTH; i++) {
    printf("%02x", md5[i]);
  }
}

void SetRandomIv(int len, char *iv) {
  for (int id = 0; id < len; id++) {
    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<int> uchr(0, 256);
    iv[id] = uchr(generator);
  }
}

void SetRc4Key(RC4_KEY *key, int len, const unsigned char *data) {
  RC4_set_key(key, len, data);
}

void GetRc4Key(unsigned char *rc4_key, unsigned char *key, size_t key_len,
               unsigned char *iv, size_t iv_len) {
  MD5_CTX ctx;
  MD5_Init(&ctx);
  MD5_Update(&ctx, key, key_len);
  MD5_Update(&ctx, iv, iv_len);
  MD5_Final(rc4_key, &ctx);
}

void Rc4Encrypt(RC4_KEY *key, size_t len, const unsigned char *indata,
                unsigned char *outdata) {
  RC4(key, len, indata, outdata);
}
