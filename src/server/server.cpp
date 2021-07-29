/*
 * @Author: V4kst1z (dcydane@gmail.com)
 * @Date: 2021-07-22 16:16:56
 * @LastEditors: V4kst1z
 * @Description: 服务端实现
 * @FilePath: /lightsocks/src/server/server.cpp
 */

#include "server/server.h"

#include <csignal>
#include <cstring>

#include "AsyncDns.h"
#include "Client.h"
#include "Looper.h"

LightSocksServer::LightSocksServer(int io_threads_num, int timer_num,
                                   unsigned short port, uint8_t tpool_num)
    : Server(io_threads_num, timer_num, port, tpool_num),
      client_loop_(new Looper<TcpConnection>()),
      dns_query_(make_unique<AsyncDns>()),
      port_(port) {
  this->SetNewConnCallback(std::bind(&LightSocksServer::NewConnectionCB, this,
                                     std::placeholders::_1));
  this->SetMessageCallBack(std::bind(&LightSocksServer::MessageCB, this,
                                     std::placeholders::_1,
                                     std::placeholders::_2));
  this->SetCloseCallBack(
      std::bind(&LightSocksServer::CloseCB, this, std::placeholders::_1));
  this->SetErrorCallBack(
      std::bind(&LightSocksServer::ErrorCB, this, std::placeholders::_1));

  client_loop_->SetLoopFlag(LOOPFLAG::CLIENT);
  client_loop_->Start();
  dns_query_->StartLoop();
  signal(SIGPIPE, SIG_IGN);
}

void LightSocksServer::NewConnectionCB(
    const std::shared_ptr<TcpConnection> &conn) {
  auto peer = conn->GetPeerAddr();
  conn_status.insert({conn.get(), CONNSTATUS::NONE});
  DEBUG << "client at " << peer->GetIp() << ":" << peer->GetPort();
}

void LightSocksServer::MessageCB(const std::shared_ptr<TcpConnection> &conn,
                                 IOBuffer &buf) {
  switch (conn_status[conn.get()]) {
    case CONNSTATUS::NONE: {
      conn_status[conn.get()] = CONNSTATUS::SEND;
      char *buff = const_cast<char *>(buf.GetReadAblePtr());
      auto enc =
          std::shared_ptr<EncryptBase>(EncryptBaseFactory::GetEncryptInstance(
              encrypt_name_, passwd_, key_len_, iv_len_));
      size_t len = buf.GetReadAbleSize() - iv_len_;
      if (len <= 0) return;
      char *data = (char *)malloc(len);

      conn_to_decrypt_.insert({conn.get(), enc});
      enc->ResetIvAndKey(buff);
      enc->DecryptData(len, (const unsigned char *)(buff + iv_len_),
                       (unsigned char *)data);

      ConnInfo *c_info = new ConnInfo;
      int header_len = ParseConnInfo(c_info, data);

      switch (c_info->addr_type_) {
        case IPV4ATYP: {
          char ip_str[INET_ADDRSTRLEN];
          inet_ntop(AF_INET, c_info->dest_addr_.ipv4_, ip_str, INET_ADDRSTRLEN);
          ConnectToAddr(ip_str, ntohs(c_info->port_), data, header_len,
                        len - header_len, conn);
        } break;
        case IPV6ATYP: {
          ERROR << "ipv6 is not supported";
        } break;
        case DOMAATYP: {
          dns_query_->AddDnsQuery(
              c_info->dest_addr_.domain_,
              std::bind(&LightSocksServer::ConnectToAddr, this,
                        std::placeholders::_1, ntohs(c_info->port_), data,
                        header_len, len - header_len, conn));
        } break;
        default:
          break;
      }
      delete c_info;
    } break;
    case CONNSTATUS::SEND: {
      char *buff = const_cast<char *>(buf.GetReadAblePtr());
      size_t len = buf.GetReadAbleSize();
      char *data = (char *)malloc(len);
      auto enc = conn_to_decrypt_[conn.get()];
      enc->DecryptData(len, (const unsigned char *)(buff),
                       (unsigned char *)data);

      if (conn_to_cli_.find(conn.get()) == conn_to_cli_.end()) {
        std::lock_guard<std::mutex> lck(send_mtx_);
        conn_to_send_[conn.get()].push_back({data, len});
      } else {
        auto cli = conn_to_cli_[conn.get()].lock();
        if (cli) cli->SendData(data, len, true);
      }
    } break;
    default:
      DEBUG << "STATUS Error~";
      break;
  }
  buf.ResetId();
}

void LightSocksServer::ConnectToAddr(std::string domain_ip, unsigned short port,
                                     char *data, int pos, int len,
                                     const std::weak_ptr<TcpConnection> conn) {
  auto ip = std::make_shared<Ipv4Addr>(domain_ip.c_str(), port);
  auto client = std::make_shared<Client>(client_loop_, ip, false, true);

  auto cli_conn = conn.lock();
  if (!cli_conn.get()) return;

  client->SetMessageCallBack([&, conn](
                                 const std::shared_ptr<TcpConnection> &conn_ser,
                                 IOBuffer &buff) {
    auto cli_conn = conn.lock();
    if (!cli_conn) return;

    int len = buff.GetReadAbleSize();
    unsigned char *buffer;

    std::shared_ptr<EncryptBase> enc;
    if (conn_to_encrypt_.find(cli_conn.get()) == conn_to_encrypt_.end()) {
      enc = std::shared_ptr<EncryptBase>(EncryptBaseFactory::GetEncryptInstance(
          encrypt_name_, passwd_, key_len_, iv_len_));
      conn_to_encrypt_.insert({cli_conn.get(), enc});
      len += iv_len_;
      buffer = (unsigned char *)malloc(len);
      memcpy(buffer, enc->GetIvPtr(), iv_len_);
      enc->EncryptData(len - iv_len_,
                       (const unsigned char *)(buff.GetReadAblePtr()),
                       buffer + iv_len_);
      cli_conn->SendData(buffer, len, true);

    } else {
      enc = conn_to_encrypt_[cli_conn.get()];
      buffer = (unsigned char *)malloc(len);
      enc->EncryptData(len, (const unsigned char *)(buff.GetReadAblePtr()),
                       buffer);
      cli_conn->SendData(buffer, len, true);
    }

    buff.ResetId();
  });

  client->SetCloseCallBack(
      [&, conn](const std::shared_ptr<TcpConnection> &conn_ser) {
        auto cli_conn = conn.lock();
        cli_to_conn_.erase(conn_to_cli_[cli_conn.get()].lock());
        conn_to_encrypt_.erase(cli_conn.get());
      });

  client->Connect();
  if (len > 0) client->SendData(data + pos, len);

  free(data);
  cli_to_conn_.insert({client, conn});
  conn_to_cli_.insert({conn.lock().get(), client});

  if (conn_to_send_.find(cli_conn.get()) != conn_to_send_.end()) {
    std::lock_guard<std::mutex> lck(send_mtx_);
    for (auto &pi : conn_to_send_[cli_conn.get()]) {
      client->SendData(pi.first, pi.second, true);
    }
    conn_to_send_.erase(cli_conn.get());
  }
}

int LightSocksServer::ParseConnInfo(ConnInfo *c_info, char *data) {
  int len = 1;
  c_info->addr_type_ = (unsigned char)*data;

  switch (c_info->addr_type_) {
    case IPV4ATYP: {
      memcpy(&c_info->dest_addr_, data + 1, 4);
      memcpy(&c_info->port_, data + 5, 2);
      len += 6;
    } break;
    case IPV6ATYP: {
      memcpy(&c_info->dest_addr_, data + 1, 16);
      memcpy(&c_info->port_, data + 17, 2);
      len += 18;
    } break;
    case DOMAATYP: {
      c_info->dest_addr_.domain_len_ = static_cast<unsigned short>(*(data + 1));
      memcpy(c_info->dest_addr_.domain_, data + 2,
             c_info->dest_addr_.domain_len_);
      c_info->dest_addr_.domain_[c_info->dest_addr_.domain_len_] = '\x00';
      memcpy(&c_info->port_, data + 2 + c_info->dest_addr_.domain_len_, 2);
      len += 1 + c_info->dest_addr_.domain_len_ + 2;
    } break;
    default:
      break;
  }
  return len;
}

void LightSocksServer::CloseCB(const std::shared_ptr<TcpConnection> &conn) {
  auto peer = conn->GetPeerAddr();
  conn_status.erase(conn.get());
  conn_to_cli_.erase(conn.get());
  conn_to_decrypt_.erase(conn.get());
  DEBUG << "close at " << peer->GetIp() << ":" << peer->GetPort();
}

void LightSocksServer::ErrorCB(const std::shared_ptr<TcpConnection> &conn) {
  if (conn_status.find(conn.get()) == conn_status.end()) return;
  auto peer = conn->GetPeerAddr();
  conn_status.erase(conn.get());
  conn_to_cli_.erase(conn.get());
  conn_to_decrypt_.erase(conn.get());
  DEBUG << "Error at " << peer->GetIp() << ":" << peer->GetPort();
}

void LightSocksServer::SetEncryptInfo(size_t k_len, size_t i_len,
                                      std::string pw, std::string e_name) {
  key_len_ = k_len;
  iv_len_ = i_len;
  passwd_ = pw;
  encrypt_name_ = e_name;
}

LightSocksServer::~LightSocksServer() {
  client_loop_->Stop();
  delete client_loop_;
}
