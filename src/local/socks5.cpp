/*
 * @Author: V4kst1z (dcydane@gmail.com)
 * @Date: 2021-07-17 21:59:29
 * @LastEditors: V4kst1z
 * @Description: socks5 协议 parse 实现
 * @FilePath: /lightsocks/src/local/socks5.cpp
 */

#include "local/socks5.h"

#include <cstring>

AUTHMETHOD
ParseReq(const char *str) {
  SocksReq req;
  memcpy(&req, str, sizeof(SocksReq));
  if (static_cast<unsigned char>(req.version_) == '\x05') {
    for (unsigned short id = 0;
         id < static_cast<unsigned short>(req.num_methods_); id++) {
      switch (*(str + id + 2)) {
        case '\x00':
          DEBUG << "NOAUTH~";
          return AUTHMETHOD::NOAUTH;
        case '\x02':
          DEBUG << "AUTH not supported~";
          return AUTHMETHOD::AUTH;
        default:
          DEBUG << "NO available method~";
          return AUTHMETHOD::NOMETHOD;
      }
    }
  }
  ERROR << "Only Supported socks5~";
  return AUTHMETHOD::NOMETHOD;
}

SocksAuthReq *ParseAuthReq(const char *str) {
  SocksAuthReq *req = new SocksAuthReq;
  memcpy(req, str, 4);

  switch (req->atyp_) {
    case IPV4ATYP: {
      memcpy(&req->dest_addr_, str + 4, 4);
      memcpy(&req->port_, str + 8, 2);
    } break;
    case IPV6ATYP: {
      memcpy(&req->dest_addr_, str + 4, 16);
      memcpy(&req->port_, str + 20, 2);
    } break;
    case DOMAATYP: {
      req->dest_addr_.domain_len_ = static_cast<unsigned short>(*(str + 4));
      memcpy(req->dest_addr_.domain_, str + 5, req->dest_addr_.domain_len_);
      req->dest_addr_.domain_[req->dest_addr_.domain_len_] = '\x00';
      memcpy(&req->port_, str + 4 + 1 + req->dest_addr_.domain_len_, 2);
    } break;
    default:
      break;
  }
  return req;
}
