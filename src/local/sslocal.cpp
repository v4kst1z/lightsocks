/*
 * @Author: V4kst1z (dcydane@gmail.com)
 * @Date: 2021-07-16 18:14:30
 * @LastEditors: V4kst1z
 * @Description: sslocal 实现
 * @FilePath: /lightsocks/src/local/sslocal.cpp
 */

#include <csignal>
#include <cstring>
#include <iostream>

#include "local/local.h"

int main(int argc, char **argv) {
  std::string passwd;
  std::string encrypt_name;
  std::string server;
  int s_port = 0;
  int l_port = 0;
  int ret;

  while ((ret = getopt(argc, argv, "s:p:l:k:m:")) != -1) {
    switch (ret) {
      case 's':
        server = optarg;
        break;
      case 'p':
        s_port = std::atoi(optarg);
        break;
      case 'l':
        l_port = std::atoi(optarg);
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

  LightSocksLocal local = LightSocksLocal(5, 1, l_port, 0);
  local.SetLocalInfo(16, 16, passwd, encrypt_name, s_port, server);
  local.LoopStart();
}
