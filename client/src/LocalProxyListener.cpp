#pragma once
#include <boost/asio.hpp>
#include <memory>
#include "LocalProxySession.h"
#include "VpnTransport.h" // Убедись, что заголовок подключен

namespace Vpn::Client {

    using boost::asio::ip::tcp;

    class LocalProxyListener {
    public:
        // Принимаем готовый vpnTransport вместо IP и порта
        LocalProxyListener(boost::asio::io_context& io, uint16_t localPort, std::shared_ptr<VpnTransport> transport)
            : m_acceptor(io, tcp::endpoint(tcp::v4(), localPort)),
            m_transport(std::move(transport)) {
        }

        void Start() { DoAccept(); }

    private:
        void DoAccept() {
            m_acceptor.async_accept([this](boost::system::error_code ec, tcp::socket socket) {
                if (!ec) {
                    // Передаем ровно 2 аргумента: сокет и транспорт
                    std::make_shared<LocalProxySession>(
                        std::move(socket), m_transport
                    )->Start();
                }
                DoAccept();
                });
        }

        tcp::acceptor m_acceptor;
        std::shared_ptr<VpnTransport> m_transport;
    };

} // namespace Vpn::Client