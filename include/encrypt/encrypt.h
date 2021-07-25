/*
 * @Author: V4kst1z (dcydane@gmail.com)
 * @Date: 2021-07-23 10:41:25
 * @LastEditors: V4kst1z
 * @Description: openssl wrapper 头文件
 * @FilePath: /lightsocks/include/encrypt/encrypt.h
 */

#ifndef LIGHTSOCKS_INCLUDE_ENCRYPT_ENCRYPT_H_
#define LIGHTSOCKS_INCLUDE_ENCRYPT_ENCRYPT_H_

#include <iostream>

#include "openssl/rc4.h"

char *GetKey(std::string &, size_t, size_t);

void SetRandomIv(int len, char *iv);

void PrintMd5(unsigned char *);

void SetRc4Key(RC4_KEY *, int, const unsigned char *);

void GetRc4Key(unsigned char *, unsigned char *, size_t, unsigned char *,
               size_t);

void Rc4Encrypt(RC4_KEY *, size_t, const unsigned char *, unsigned char *);

#endif  // LIGHTSOCKS_INCLUDE_ENCRYPT_ENCRYPT_H_
