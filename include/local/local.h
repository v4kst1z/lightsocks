/*
 * @Author: V4kst1z (dcydane@gmail.com)
 * @Date: 2021-07-16 18:15:45
 * @LastEditors: V4kst1z
 * @Description: 本地 local 头文件
 * @FilePath: /lightsocks/include/local/local.h
 */

#ifndef LIGHTSOCKS_INCLUDE_LOCAL_LOCAL_H_
#define LIGHTSOCKS_INCLUDE_LOCAL_LOCAL_H_

#include "Server.h"

class Client;
struct SocksAuthReq;

enum class CONNSTATUS {
  REQ,
  AUTH,
  CONN,
};

class LightSocksLocal : public Server {
 public:
  using CliToConn =
      std::unordered_map<std::shared_ptr<Client>, std::weak_ptr<TcpConnection>>;
  using ConnToCli = std::unordered_map<TcpConnection *, std::weak_ptr<Client>>;

  LightSocksLocal(int io_threads_num = 5, int timer_num = 1,
                  unsigned short port = 9999, uint8_t tpool_num = 0);

  void NewConnectionCB(const std::shared_ptr<TcpConnection> &conn);

  void MessageCB(const std::shared_ptr<TcpConnection> &conn, IOBuffer &buf);

  void CloseCB(const std::shared_ptr<TcpConnection> &conn);

  void ErrorCB(const std::shared_ptr<TcpConnection> &conn);

  ~LightSocksLocal();

  DISALLOW_COPY_AND_ASSIGN(LightSocksLocal);

 private:
  void ConnectToAddr(SocksAuthReq *, const std::weak_ptr<TcpConnection> conn);

  std::unordered_map<TcpConnection *, CONNSTATUS> conn_status;
  CliToConn cli_to_conn_;
  ConnToCli conn_to_cli_;
  Looper<TcpConnection> *client_loop_;
};

#endif  // LIGHTSOCKS_INCLUDE_LOCAL_LOCAL_H_
