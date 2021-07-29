/*
 * @Author: V4kst1z (dcydane@gmail.com)
 * @Date: 2021-07-22 16:10:06
 * @LastEditors: V4kst1z
 * @Description: 服务端头文件
 * @FilePath: /lightsocks/include/server/server.h
 */

#ifndef LIGHTSOCKS_INCLUDE_SERVER_SERVER_H_
#define LIGHTSOCKS_INCLUDE_SERVER_SERVER_H_

#include "Server.h"
#include "encrypt/encrypt_base.h"

class Client;
class TcpConnection;
class AsyncDns;

enum class CONNSTATUS { NONE, SEND };

#define IPV4ATYP '\x01'
#define DOMAATYP '\x03'
#define IPV6ATYP '\x04'

struct ConnInfo {
  unsigned char addr_type_;
  union {
    char ipv4_[4];
    char ipv6_[16];
    struct {
      unsigned char domain_len_;
      char domain_[256];
    };
  } __attribute__((packed)) dest_addr_;
  unsigned short port_;
};

class LightSocksServer : public Server {
 public:
  using CliToConn =
      std::unordered_map<std::shared_ptr<Client>, std::weak_ptr<TcpConnection>>;
  using ConnToCli = std::unordered_map<TcpConnection *, std::weak_ptr<Client>>;
  using ConnToEnc =
      std::unordered_map<TcpConnection *, std::shared_ptr<EncryptBase>>;
  using ConnToSend =
      std::unordered_map<TcpConnection *, std::vector<std::pair<char *, int>>>;

  LightSocksServer(int io_threads_num = 5, int timer_num = 1,
                   unsigned short port = 12111, uint8_t tpool_num = 0);

  void NewConnectionCB(const std::shared_ptr<TcpConnection> &conn);

  void MessageCB(const std::shared_ptr<TcpConnection> &conn, IOBuffer &buf);

  void CloseCB(const std::shared_ptr<TcpConnection> &conn);

  void ErrorCB(const std::shared_ptr<TcpConnection> &conn);

  void SetEncryptInfo(size_t, size_t, std::string, std::string);

  int ParseConnInfo(ConnInfo *, char *buff);

  ~LightSocksServer();

  DISALLOW_COPY_AND_ASSIGN(LightSocksServer);

 private:
  void ConnectToAddr(std::string, unsigned short, char *, int, int,
                     const std::weak_ptr<TcpConnection>);

  Looper<TcpConnection> *client_loop_;
  std::unique_ptr<AsyncDns> dns_query_;

  ConnToEnc conn_to_decrypt_;
  ConnToEnc conn_to_encrypt_;

  CliToConn cli_to_conn_;
  ConnToCli conn_to_cli_;
  std::unordered_map<TcpConnection *, CONNSTATUS> conn_status;

  ConnToSend conn_to_send_;
  std::mutex send_mtx_;

  size_t key_len_;
  size_t iv_len_;
  std::string passwd_;
  std::string encrypt_name_;
  unsigned short port_;
};

#endif  // LIGHTSOCKS_INCLUDE_SERVER_SERVER_H_
