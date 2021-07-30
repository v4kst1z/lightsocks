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
      io_nums_(io_threads_num),
      io_idx_(0),
      io_threads_(GetIoLoop()) {
  this->SetNewConnCallback(std::bind(&LightSocksLocal::NewConnectionCB, this,
                                     std::placeholders::_1));
  this->SetMessageCallBack(std::bind(&LightSocksLocal::MessageCB, this,
                                     std::placeholders::_1,
                                     std::placeholders::_2));
  this->SetCloseCallBack(
      std::bind(&LightSocksLocal::CloseCB, this, std::placeholders::_1));
  this->SetErrorCallBack(
      std::bind(&LightSocksLocal::ErrorCB, this, std::placeholders::_1));
}

void LightSocksLocal::NewConnectionCB(
    const std::shared_ptr<TcpConnection> &conn) {
  auto peer = conn->GetPeerAddr();
  DEBUG << "client at " << peer->GetIp() << ":" << peer->GetPort();

  auto enc =
      std::shared_ptr<EncryptBase>(EncryptBaseFactory::GetEncryptInstance(
          encrypt_name_, passwd_, key_len_, iv_len_));
  {
    std::lock_guard<std::mutex> lck(encrypt_mtx_);
    conn_to_encrypt_.insert({conn.get(), enc});
  }
  {
    std::lock_guard<std::mutex> lck(conn_mtx_);
    conn_status.insert({conn.get(), CONNSTATUS::REQ});
  }
}

void LightSocksLocal::MessageCB(const std::shared_ptr<TcpConnection> &conn,
                                IOBuffer &buf) {
  if (!conn) return;
  const char *str = buf.GetReadAblePtr();
  CONNSTATUS status;
  {
    std::lock_guard<std::mutex> lck(conn_mtx_);
    status = conn_status[conn.get()];
  }
  switch (status) {
    case CONNSTATUS::REQ: {
      if (ParseReq(str) == AUTHMETHOD::NOAUTH) {
        SocksRes res;
        res.version_ = '\x05';
        res.method_ = '\x00';
        conn->SendData(&res, 2);
      }
      {
        std::lock_guard<std::mutex> lck(conn_mtx_);
        conn_status[conn.get()] = CONNSTATUS::AUTH;
      }
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
          {
            std::lock_guard<std::mutex> lck(conn_mtx_);
            conn_status[conn.get()] = CONNSTATUS::CONN;
          }
          ConnectToAddr(req, conn);
        } else {
          DEBUG << "IPv6 is not supported~";
        }
      } else {
        DEBUG << "Auth Error~";
      }
      delete req;
    } break;
    case CONNSTATUS::CONN: {
      std::shared_ptr<EncryptBase> enc;
      {
        std::lock_guard<std::mutex> lck(encrypt_mtx_);
        enc = conn_to_encrypt_[conn.get()];
      }
      char *data = (char *)malloc(buf.GetReadAbleSize());
      char *buffer = (char *)buf.GetReadAblePtr();
      enc->EncryptData(buf.GetReadAbleSize(),
                       (const unsigned char *)buf.GetReadAblePtr(),
                       (unsigned char *)data);
      std::shared_ptr<Client> cli;
      {
        std::lock_guard<std::mutex> lck(cli_mtx_);
        cli = conn_to_cli_[conn.get()].lock();
      }
      if (cli) cli->SendData(data, buf.GetReadAbleSize(), true);
    } break;
    default:
      DEBUG << "STATUS Error~";
      break;
  }
  buf.ResetId();
}

void LightSocksLocal::ConnectToAddr(SocksAuthReq *req,
                                    const std::weak_ptr<TcpConnection> conn) {
  auto ip = std::make_shared<Ipv4Addr>(server_ip_.c_str(), port_);
  auto client = std::make_shared<Client>(io_threads_[io_idx_++ % io_nums_], ip,
                                         false, true);

  int buff_len = 0;
  char *buff_send;
  char *data;
  switch (req->atyp_) {
    case IPV4ATYP: {
      buff_len = 7 + iv_len_;
      buff_send = (char *)malloc(buff_len);
      data = (char *)malloc(buff_len - iv_len_);
      data[0] = (unsigned char)req->atyp_;
      memcpy(data + 1, req->dest_addr_.ipv4_, 4);
      memcpy(data + 5, &req->port_, 2);
    } break;
    case DOMAATYP: {
      buff_len = 2 + req->dest_addr_.domain_len_ + 2 + iv_len_;
      buff_send = (char *)malloc(buff_len);
      data = (char *)malloc(buff_len - iv_len_);
      data[0] = (unsigned char)req->atyp_;
      data[1] = (unsigned char)req->dest_addr_.domain_len_;
      memcpy(data + 2, req->dest_addr_.domain_, req->dest_addr_.domain_len_);
      memcpy(data + 2 + req->dest_addr_.domain_len_, &req->port_, 2);
    } break;
    default:
      ERROR << "address type is not supported~";
      return;
  }

  auto conn_lck = conn.lock();
  if (!conn_lck) return;
  std::shared_ptr<EncryptBase> enc;
  {
    std::lock_guard<std::mutex> lck(encrypt_mtx_);
    enc = conn_to_encrypt_[conn_lck.get()];
  }
  memcpy(buff_send, enc->GetIvPtr(), iv_len_);
  enc->EncryptData(buff_len - iv_len_, (const unsigned char *)data,
                   (unsigned char *)(buff_send + iv_len_));
  free(data);

  client->SetMessageCallBack([this, conn](
                                 const std::shared_ptr<TcpConnection> &conn_ser,
                                 IOBuffer &buff) {
    auto w_conn = conn.lock();
    char *buf = const_cast<char *>(buff.GetReadAblePtr());
    char *data;
    int len = buff.GetReadAbleSize() - iv_len_;

    if (len <= 0) return;

    bool not_find;
    {
      std::lock_guard<std::mutex> lck(decrypt_mtx_);
      not_find = conn_to_decrypt_.find(w_conn.get()) == conn_to_decrypt_.end();
    }

    if (not_find) {
      data = (char *)malloc(len);
      auto enc =
          std::shared_ptr<EncryptBase>(EncryptBaseFactory::GetEncryptInstance(
              encrypt_name_, passwd_, key_len_, iv_len_));
      enc->ResetIvAndKey(buf);
      {
        std::lock_guard<std::mutex> lck(decrypt_mtx_);
        conn_to_decrypt_.insert({w_conn.get(), enc});
      }
      enc->DecryptData(len,
                       (const unsigned char *)(buff.GetReadAblePtr() + iv_len_),
                       (unsigned char *)data);
      if (w_conn) w_conn->SendData(data, len, true);

    } else {
      std::shared_ptr<EncryptBase> enc;
      {
        std::lock_guard<std::mutex> lck(decrypt_mtx_);
        enc = conn_to_decrypt_[w_conn.get()];
      }
      data = (char *)malloc(buff.GetReadAbleSize());
      enc->DecryptData(buff.GetReadAbleSize(),
                       (const unsigned char *)(buff.GetReadAblePtr()),
                       (unsigned char *)data);
      if (w_conn) w_conn->SendData(data, buff.GetReadAbleSize(), true);
    }

    buff.ResetId();
  });

  client->SetCloseCallBack(
      [this, conn](const std::shared_ptr<TcpConnection> &conn_ser) {
        auto conn_lck = conn.lock();
        if (!conn_lck) return;
        {
          std::lock_guard<std::mutex> lck(cli_mtx_);
          cli_to_conn_.erase(conn_to_cli_[conn_lck.get()].lock());
          conn_to_cli_.erase(conn_lck.get());
        }
        {
          std::lock_guard<std::mutex> lck(decrypt_mtx_);
          conn_to_decrypt_.erase(conn_lck.get());
        }
      });

  client->Connect();
  client->SendData(buff_send, buff_len, true);
  {
    std::lock_guard<std::mutex> lck(cli_mtx_);
    cli_to_conn_.insert({client, conn});
    conn_to_cli_.insert({conn_lck.get(), client});
  }
}

void LightSocksLocal::CloseCB(const std::shared_ptr<TcpConnection> &conn) {
  auto peer = conn->GetPeerAddr();
  DEBUG << "close at " << peer->GetIp() << ":" << peer->GetPort();
  {
    std::lock_guard<std::mutex> lck(encrypt_mtx_);
    conn_to_encrypt_.erase(conn.get());
  }
  {
    std::lock_guard<std::mutex> lck(conn_mtx_);
    conn_status.erase(conn.get());
  }
}

void LightSocksLocal::ErrorCB(const std::shared_ptr<TcpConnection> &conn) {
  auto peer = conn->GetPeerAddr();
  DEBUG << "Error at " << peer->GetIp() << ":" << peer->GetPort();
  {
    std::lock_guard<std::mutex> lck(encrypt_mtx_);
    conn_to_encrypt_.erase(conn.get());
  }
  {
    std::lock_guard<std::mutex> lck(conn_mtx_);
    conn_status.erase(conn.get());
  }
}

void LightSocksLocal::SetLocalInfo(size_t k_len, size_t i_len, std::string pw,
                                   std::string e_name, unsigned short port,
                                   std::string ip) {
  key_len_ = k_len;
  iv_len_ = i_len;
  passwd_ = pw;
  encrypt_name_ = e_name;
  port_ = port;
  server_ip_ = ip;
}

LightSocksLocal::~LightSocksLocal() {}
