/*
 * @Author: V4kst1z (dcydane@gmail.com)
 * @Date: 2021-07-22 16:34:31
 * @LastEditors: V4kst1z
 * @Description: ssserver 实现
 * @FilePath: /lightsocks/src/server/ssserver.cpp
 */

#include <csignal>
#include <cstring>
#include <iostream>

#include "encrypt/encrypt.h"
#include "encrypt/encrypt_base.h"
#include "server/server.h"

int main() {
  signal(SIGPIPE, SIG_IGN);
  LightSocksServer server = LightSocksServer();
  server.SetEncryptInfo(16, 16, "V4kst1z", "rc4-md5", 9999, 1000);
  server.LoopStart();
}
