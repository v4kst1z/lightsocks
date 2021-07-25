/*
 * @Author: V4kst1z (dcydane@gmail.com)
 * @Date: 2021-07-19 19:38:36
 * @LastEditors: V4kst1z
 * @Description: 本地 local 实现
 * @FilePath: /lightsocks/src/local/local.cpp
 */

#include "local/local.h"

#include <csignal>
#include <cstring>

#include "Client.h"
#include "local/socks5.h"

LightSocksLocal::LightSocksLocal(int io_threads_num, int timer_num,
                                 unsigned short port, uint8_t tpool_num)
    : Server(io_threads_num, timer_num, port, tpool_num),
      client_loop_(new Looper<TcpConnection>()) {
  this->SetNewConnCallback(std::bind(&LightSocksLocal::NewConnectionCB, this,
                                     std::placeholders::_1));
  this->SetMessageCallBack(std::bind(&LightSocksLocal::MessageCB, this,
                                     std::placeholders::_1,
                                     std::placeholders::_2));
  this->SetCloseCallBack(
      std::bind(&LightSocksLocal::CloseCB, this, std::placeholders::_1));
  this->SetErrorCallBack(
      std::bind(&LightSocksLocal::ErrorCB, this, std::placeholders::_1));
  client_loop_->SetLoopFlag(LOOPFLAG::CLIENT);
  client_loop_->Start();
  signal(SIGPIPE, SIG_IGN);
}

void LightSocksLocal::NewConnectionCB(
    const std::shared_ptr<TcpConnection> &conn) {
  auto peer = conn->GetPeerAddr();
  DEBUG << "client at " << peer->GetIp() << ":" << peer->GetPort();
  conn_status.insert({conn.get(), CONNSTATUS::REQ});
}

void LightSocksLocal::MessageCB(const std::shared_ptr<TcpConnection> &conn,
                                IOBuffer &buf) {
  if (!conn) return;
  const char *str = buf.GetReadAblePtr();
  switch (conn_status[conn.get()]) {
    case CONNSTATUS::REQ: {
      if (ParseReq(str) == AUTHMETHOD::NOAUTH) {
        SocksRes res;
        res.version_ = '\x05';
        res.method_ = '\x00';
        conn->SendData(&res, 2);
      }
      conn_status[conn.get()] = CONNSTATUS::AUTH;
    } break;
    case CONNSTATUS::AUTH: {
      SocksAuthReq *req = ParseAuthReq(str);
      if (req->version_ == '\x05' && req->cmd_ == '\x01') {
        if (req->atyp_ == IPV4ATYP || req->atyp_ == DOMAATYP) {
          SocksAuthRes res;
          res.version_ = '\x05';
          res.rep_ = '\x00';
          res.rsv_ = '\x00';
          res.atyp_ = '\x01';
          res.ipv4_ = htonl(INADDR_ANY);
          res.port_ = htons(9999);
          conn->SendData(&res, sizeof(res));
          conn_status[conn.get()] = CONNSTATUS::CONN;
          if (req->atyp_ == DOMAATYP) ConnectToAddr(req, conn);
        } else {
          DEBUG << "IPv6 is not supported~";
        }
      } else {
        DEBUG << "Auth Error~";
      }
      delete req;
    } break;
    case CONNSTATUS::CONN: {
      auto cli = conn_to_cli_[conn.get()].lock();
      if (cli) cli->SendData(&buf);
    } break;
    default:
      DEBUG << "STATUS Error~";
      break;
  }
  buf.ResetId();
}

void LightSocksLocal::CloseCB(const std::shared_ptr<TcpConnection> &conn) {
  auto peer = conn->GetPeerAddr();
  conn_status.erase(conn.get());
  DEBUG << "close at " << peer->GetIp() << ":" << peer->GetPort();
}

void LightSocksLocal::ErrorCB(const std::shared_ptr<TcpConnection> &conn) {
  auto peer = conn->GetPeerAddr();
  conn_status.erase(conn.get());
  DEBUG << "Error at " << peer->GetIp() << ":" << peer->GetPort();
}

void LightSocksLocal::ConnectToAddr(SocksAuthReq *req,
                                    const std::weak_ptr<TcpConnection> conn) {
  auto ip =
      std::make_shared<Ipv4Addr>(req->dest_addr_.domain_, ntohs(req->port_));
  // auto ip = std::make_shared<Ipv4Addr>(8888);
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
  cli_to_conn_.insert({client, conn});
  conn_to_cli_.insert({conn.lock().get(), client});
}

LightSocksLocal::~LightSocksLocal() {
  client_loop_->Stop();
  delete client_loop_;
}
