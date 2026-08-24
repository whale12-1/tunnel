#include "FallbackRelay.h"
#include "TLSHelper.h"
#include <iostream>

static const std::unordered_set<std::string> ALLOWED_SNIS = {
        "dl.google.com", "cloud.google.com", "www.google.com"
};

namespace Vpn::Server {

    FallbackRelay::FallbackRelay(tcp::socket clientSocket)
        : m_clientSocket(std::move(clientSocket)),
        m_fallbackSocket(m_clientSocket.get_executor()) {
    }

    void FallbackRelay::Start(std::shared_ptr<std::vector<uint8_t>> initialPacket) {
        auto self = shared_from_this();
        std::string sniHost;
        bool parsed = Vpn::Protocol::TlsHelper::ParseSniFromClientHello(*initialPacket, sniHost);

        if (!parsed || ALLOWED_SNIS.find(sniHost) == ALLOWED_SNIS.end()) {
            sniHost = "dl.google.com";
        }

        auto resolver = std::make_shared<tcp::resolver>(m_clientSocket.get_executor());
        resolver->async_resolve(sniHost, "443",
            [this, self, initialPacket, resolver](boost::system::error_code ec, tcp::resolver::results_type endpoints) {
                if (ec) { CloseAll(); return; }

                boost::asio::async_connect(m_fallbackSocket, endpoints,
                    [this, self, initialPacket](boost::system::error_code connectEc, const tcp::endpoint&) {
                        if (connectEc) { CloseAll(); return; }

                        boost::asio::async_write(m_fallbackSocket, boost::asio::buffer(*initialPacket),
                            [this, self](boost::system::error_code writeEc, size_t) {
                                if (writeEc) { CloseAll(); return; }
                                StartRawRelaying();
                            });
                    });
            });
    }

    void FallbackRelay::StartRawRelaying() {
        RelayClientToFallback();
        RelayFallbackToClient();
    }

    void FallbackRelay::RelayClientToFallback() {
        auto self = shared_from_this();
        m_clientSocket.async_read_some(boost::asio::buffer(m_c2fBuffer),
            [this, self](boost::system::error_code ec, size_t length) {
                if (ec) { CloseAll(); return; }
                boost::asio::async_write(m_fallbackSocket, boost::asio::buffer(m_c2fBuffer.data(), length),
                    [this, self](boost::system::error_code writeEc, size_t) {
                        if (writeEc) { CloseAll(); return; }
                        RelayClientToFallback();
                    });
            });
    }

    void FallbackRelay::RelayFallbackToClient() {
        auto self = shared_from_this();
        m_fallbackSocket.async_read_some(boost::asio::buffer(m_f2cBuffer),
            [this, self](boost::system::error_code ec, size_t length) {
                if (ec) { CloseAll(); return; }
                boost::asio::async_write(m_clientSocket, boost::asio::buffer(m_f2cBuffer.data(), length),
                    [this, self](boost::system::error_code writeEc, size_t) {
                        if (writeEc) { CloseAll(); return; }
                        RelayFallbackToClient();
                    });
            });
    }

    void FallbackRelay::CloseAll() {
        boost::system::error_code ec;
        if (m_clientSocket.is_open()) m_clientSocket.close(ec);
        if (m_fallbackSocket.is_open()) m_fallbackSocket.close(ec);
    }

} // namespace Vpn::Server