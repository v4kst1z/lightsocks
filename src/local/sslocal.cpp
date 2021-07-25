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

int main() {
  signal(SIGPIPE, SIG_IGN);
  LightSocksLocal local = LightSocksLocal();
  local.LoopStart();
}
