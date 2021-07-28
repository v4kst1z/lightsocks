/*
 * @Author: V4kst1z (dcydane@gmail.com)
 * @Date: 2021-07-17 20:05:03
 * @LastEditors: V4kst1z
 * @Description: socks5 协议 parse 头文件
 * @FilePath: /lightsocks/include/local/socks5.h
 */

#ifndef LIGHTSOCKS_INCLUDE_LOCAL_SOCKS5_H_
#define LIGHTSOCKS_INCLUDE_LOCAL_SOCKS5_H_

#include "Logger.h"

enum class AUTHMETHOD { NOAUTH, AUTH, NOMETHOD };

struct SocksReq {
  unsigned char version_;
  unsigned char num_methods_;
} __attribute__((packed));

struct SocksRes {
  unsigned char version_;
  unsigned char method_;
} __attribute__((packed));

#define IPV4ATYP '\x01'
#define DOMAATYP '\x03'
#define IPV6ATYP '\x04'

struct SocksAuthReq {
  unsigned char version_;
  unsigned char cmd_;
  unsigned char rsv_;
  unsigned char atyp_;
  union {
    char ipv4_[4];
    char ipv6_[16];
    struct {
      unsigned char domain_len_;
      char domain_[256];
    };
  } __attribute__((packed)) dest_addr_;
  unsigned short port_;
} __attribute__((packed));

struct SocksAuthRes {
  unsigned char version_;
  unsigned char rep_;
  unsigned char rsv_;
  unsigned char atyp_;
  unsigned int ipv4_;
  unsigned short port_;
} __attribute__((packed));

AUTHMETHOD
ParseReq(const char *str);

SocksAuthReq *ParseAuthReq(const char *);

#endif  // LIGHTSOCKS_INCLUDE_LOCAL_SOCKS5_H_
