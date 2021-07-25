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
      wakeup_dns_fd_(CreateEventFd()) {
  this->SetNewConnCallback(std::bind(&LightSocksServer::NewConnectionCB, this,
                                     std::placeholders::_1));
  this->SetMessageCallBack(std::bind(&LightSocksServer::MessageCB, this,
                                     std::placeholders::_1,
                                     std::placeholders::_2));
  this->SetCloseCallBack(
      std::bind(&LightSocksServer::CloseCB, this, std::placeholders::_1));
  this->SetErrorCallBack(
      std::bind(&LightSocksServer::ErrorCB, this, std::placeholders::_1));

  EventBase<Event> event_fd = Event(wakeup_dns_fd_);
  event_fd.EnableReadEvents(true);
  event_fd.SetReadCallback([this]() {
    char ip_str[INET_ADDRSTRLEN];
    ssize_t n = 0;
    while ((n = read(wakeup_dns_fd_, ip_str, INET_ADDRSTRLEN)) > 0) {
    }
  });

  GetMianLoop()->AddEvent(std::make_shared<VariantEventBase>(event_fd));

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
  if (!conn) return;
  switch (conn_status[conn.get()]) {
    case CONNSTATUS::NONE: {
      conn_status[conn.get()] = CONNSTATUS::SEND;
      char *buff = const_cast<char *>(buf.GetReadAblePtr());
      auto enc =
          std::shared_ptr<EncryptBase>(EncryptBaseFactory::GetEncryptInstance(
              encrypt_name_, passwd_, key_len_, iv_len_));
      size_t len = buf.GetReadAbleSize() - iv_len_;
      char *data = (char *)malloc(len);

      conn_to_enc_.insert({conn.get(), enc});
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
      size_t len = buf.GetReadAbleSize() - iv_len_;
      char *data = (char *)malloc(len + 1);
      memset(data, '\x00', len + 1);
      conn_to_enc_[conn.get()]->ResetIvAndKey(buff);
      conn_to_enc_[conn.get()]->DecryptData(
          len, (const unsigned char *)(buff + iv_len_), (unsigned char *)data);
      printf("%s\n", data);

      // char *data = (char *)malloc(buf.GetReadAbleSize());
      // conn_to_enc_[conn.get()]->DecryptData(
      //     buf.GetReadAbleSize(), (const unsigned char
      //     *)(buf.GetReadAblePtr()), (unsigned char *)data);
      // printf("%s\n", data);
      for (size_t id = 0; id < len; id++) {
        printf("%02x", (unsigned char)data[id]);
      }
      printf("\n");
      free(data);
    } break;
    default:
      DEBUG << "STATUS Error~";
      break;
  }
  auto cli = conn_to_cli_[conn.get()].lock();
  if (cli) cli->SendData(&buf);
  buf.ResetId();
}

void LightSocksServer::ConnectToAddr(std::string domain_ip, unsigned short port,
                                     char *data, int pos, int len,
                                     const std::weak_ptr<TcpConnection> conn) {
  DEBUG << "Connect to " << domain_ip << ":" << port;
  auto ip = std::make_shared<Ipv4Addr>(domain_ip.c_str(), port);
  auto client = std::make_shared<Client>(client_loop_, ip, false, true);

  client->SetMessageCallBack(
      [conn](const std::shared_ptr<TcpConnection> &conn_ser, IOBuffer &buff) {
        auto w_conn = conn.lock();
        if (w_conn) w_conn->SendData(&buff);

        buff.ResetId();
      });

  client->SetCloseCallBack(
      [this, conn](const std::shared_ptr<TcpConnection> &conn_ser) {
        cli_to_conn_.erase(conn_to_cli_[conn.lock().get()].lock());
        conn_to_cli_.erase(conn.lock().get());
      });

  client->Connect();
  client->SendData(data + pos, len);

  free(data);
  cli_to_conn_.insert({client, conn});
  conn_to_cli_.insert({conn.lock().get(), client});
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
    } break;
    default:
      break;
  }
  return len;
}

void LightSocksServer::CloseCB(const std::shared_ptr<TcpConnection> &conn) {
  auto peer = conn->GetPeerAddr();
  conn_status.erase(conn.get());
  conn_to_enc_.erase(conn.get());
  DEBUG << "close at " << peer->GetIp() << ":" << peer->GetPort();
}

void LightSocksServer::ErrorCB(const std::shared_ptr<TcpConnection> &conn) {
  auto peer = conn->GetPeerAddr();
  conn_status.erase(conn.get());
  conn_to_enc_.erase(conn.get());
  DEBUG << "Error at " << peer->GetIp() << ":" << peer->GetPort();
}

void LightSocksServer::SetEncryptInfo(size_t k_len, size_t i_len,
                                      std::string pw, std::string e_name,
                                      unsigned short port,
                                      unsigned short time_out) {
  key_len_ = k_len;
  iv_len_ = i_len;
  passwd_ = pw;
  encrypt_name_ = e_name;
  port_ = port;
  time_out_ = time_out;
}

LightSocksServer::~LightSocksServer() {
  client_loop_->Stop();
  delete client_loop_;
}
