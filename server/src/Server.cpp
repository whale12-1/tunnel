// Server.cpp
#include "Server.h"
#include "Session.h"
#include <iostream>

namespace Vpn::Server {

    Server::Server(boost::asio::io_context& ioContext, uint16_t port)
        : m_ioContext(ioContext),
        m_acceptor(ioContext, tcp::endpoint(tcp::v4(), port)),
        m_serverCrypto(std::make_shared<CryptoEngine>()) // Генерация ключа один раз при старте сервера
    {
        // Выводим публичный ключ сервера в консоль для клиента
        auto pubKey = m_serverCrypto->GetLocalPublicKey();

        // Автоматически сохраняем ключ в файл рядом с исполняемым файлом
        std::ofstream outFile("server_pub.key", std::ios::binary);
        if (outFile.is_open()) {
            outFile.write(reinterpret_cast<const char*>(pubKey.data()), pubKey.size());
            std::cout << "[VPN Server] Public key automatically saved to 'server_pub.key'\n";
        }
    }

    void Server::Start() {
        DoAccept();
    }

    void Server::DoAccept() {
        m_acceptor.async_accept(
            [this](boost::system::error_code ec, tcp::socket socket) {
                if (!ec) {
                    // Передаем общий серверный CryptoEngine в сессию клиента
                    std::make_shared<Session>(std::move(socket), m_serverCrypto)->Start();
                }
                DoAccept();
            }
        );
    }
} // namespace Vpn::Server