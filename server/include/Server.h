#pragma once

#include <boost/asio.hpp>
#include <memory>
#include "Session.h"
#include <fstream>

namespace Vpn::Server {

    using boost::asio::ip::tcp;

    class Server {
    public:
        Server(boost::asio::io_context& ioContext, uint16_t port);
        void Start();

    private:
        void DoAccept();

        boost::asio::io_context& m_ioContext;
        tcp::acceptor m_acceptor;

        std::shared_ptr<CryptoEngine> m_serverCrypto;
    };

} // namespace Vpn::Server