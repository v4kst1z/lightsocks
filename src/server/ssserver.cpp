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

int main(int argc, char **argv) {
  std::string passwd;
  std::string encrypt_name;
  int s_port = 0;
  int ret;

  while ((ret = getopt(argc, argv, "p:k:m:")) != -1) {
    switch (ret) {
      case 'p':
        s_port = std::atoi(optarg);
        break;
      case 'k':
        passwd = optarg;
        break;
      case 'm':
        encrypt_name = optarg;
        break;
      default:
        std::cout << "Not supported~" << std::endl;
        return 0;
    }
  }
  LightSocksServer server = LightSocksServer(5, 1, s_port, 0);
  server.SetEncryptInfo(16, 16, passwd, encrypt_name);
  server.LoopStart();
}
