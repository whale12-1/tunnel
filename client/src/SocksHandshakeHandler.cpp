#include "SocksHandshakeHandler.h"
#include <iostream>

namespace Vpn::Client {

    SocksHandshakeHandler::SocksHandshakeHandler(tcp::socket& appSocket)
        : m_appSocket(appSocket) {
    }

    void SocksHandshakeHandler::Start(TargetAddressCallback onTargetResolved, ErrorCallback onError) {
        m_onTargetResolved = std::move(onTargetResolved);
        m_onError = std::move(onError);
        DoReadSocksHandshake();
    }

    void SocksHandshakeHandler::DoReadSocksHandshake() {
        auto self = shared_from_this();

        boost::asio::async_read(m_appSocket, boost::asio::buffer(m_buffer, 2),
            [this, self](boost::system::error_code ec, size_t) {
                if (ec || m_buffer[0] != 0x05) {
                    std::cerr << "[Client Proxy Error] SOCKS handshake failed: " << ec.message() << "\n";
                    if (m_onError) m_onError();
                    return;
                }

                uint8_t nmethods = m_buffer[1];

                boost::asio::async_read(m_appSocket, boost::asio::buffer(m_buffer, nmethods),
                    [this, self](boost::system::error_code readEc, size_t) {
                        if (readEc) {
                            std::cerr << "[Client Proxy Error] SOCKS methods read failed: " << readEc.message() << "\n";
                            if (m_onError) m_onError();
                            return;
                        }

                        static const uint8_t response[] = { 0x05, 0x00 };
                        boost::asio::async_write(m_appSocket, boost::asio::buffer(response, 2),
                            [this, self](boost::system::error_code writeEc, size_t) {
                                if (writeEc) {
                                    std::cerr << "[Client Proxy Error] SOCKS response write failed: " << writeEc.message() << "\n";
                                    if (m_onError) m_onError();
                                    return;
                                }
                                DoReadSocksRequestHeader();
                            });
                    });
            });
    }

    void SocksHandshakeHandler::DoReadSocksRequestHeader() {
        auto self = shared_from_this();
        boost::asio::async_read(m_appSocket, boost::asio::buffer(m_buffer, 4),
            [this, self](boost::system::error_code ec, size_t) {
                if (ec || m_buffer[0] != 0x05 || m_buffer[1] != 0x01) {
                    std::cerr << "[Client Proxy Error] SOCKS request header failed: " << ec.message() << "\n";
                    if (m_onError) m_onError();
                    return;
                }
                DoReadSocksAddress(m_buffer[3]);
            });
    }

    void SocksHandshakeHandler::DoReadSocksAddress(uint8_t socksAddressType) {
        auto self = shared_from_this();

        if (socksAddressType == 0x01) { // IPv4
            boost::asio::async_read(m_appSocket, boost::asio::buffer(m_buffer, 6),
                [this, self](boost::system::error_code ec, size_t) {
                    if (ec) {
                        std::cerr << "[Client Proxy Error] IPv4 address read failed: " << ec.message() << "\n";
                        if (m_onError) m_onError();
                        return;
                    }
                    Protocol::TargetAddress target{ Protocol::AddressType::IPv4 };
                    boost::asio::ip::address_v4 ip(
                        (static_cast<uint8_t>(m_buffer[0]) << 24) | (static_cast<uint8_t>(m_buffer[1]) << 16) |
                        (static_cast<uint8_t>(m_buffer[2]) << 8) | static_cast<uint8_t>(m_buffer[3]));
                    target.address = ip.to_string();
                    target.port = (static_cast<uint8_t>(m_buffer[4]) << 8) | static_cast<uint8_t>(m_buffer[5]);

                    if (m_onTargetResolved) m_onTargetResolved(target);
                });
        }
        else if (socksAddressType == 0x03) { // Domain
            boost::asio::async_read(m_appSocket, boost::asio::buffer(m_buffer, 1),
                [this, self](boost::system::error_code ec, size_t) {
                    if (ec) {
                        std::cerr << "[Client Proxy Error] Domain length read failed: " << ec.message() << "\n";
                        if (m_onError) m_onError();
                        return;
                    }
                    uint8_t domainLen = static_cast<uint8_t>(m_buffer[0]);
                    auto domainBuf = std::make_shared<std::vector<uint8_t>>(domainLen + 2);

                    boost::asio::async_read(m_appSocket, boost::asio::buffer(*domainBuf),
                        [this, self, domainLen, domainBuf](boost::system::error_code readEc, size_t) {
                            if (readEc) {
                                std::cerr << "[Client Proxy Error] Domain name read failed: " << readEc.message() << "\n";
                                if (m_onError) m_onError();
                                return;
                            }
                            Protocol::TargetAddress target{ Protocol::AddressType::Domain };
                            target.address = std::string(reinterpret_cast<const char*>(domainBuf->data()), domainLen);
                            target.port = (static_cast<uint16_t>((*domainBuf)[domainLen]) << 8) | static_cast<uint16_t>((*domainBuf)[domainLen + 1]);

                            if (m_onTargetResolved) m_onTargetResolved(target);
                        });
                });
        }
        else {
            std::cerr << "[Client Proxy Error] Unsupported SOCKS address type: " << (int)socksAddressType << "\n";
            if (m_onError) m_onError();
        }
    }

    void SocksHandshakeHandler::SendSuccessResponse(SuccessCallback onSent, ErrorCallback onError) {
        auto self = shared_from_this();
        static const uint8_t successResponse[10] = { 0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0 };

        boost::asio::async_write(m_appSocket, boost::asio::buffer(successResponse, 10),
            [this, self, onSent = std::move(onSent), onError = std::move(onError)](boost::system::error_code ec, size_t) {
                if (ec) {
                    std::cerr << "[Client Proxy Error] SOCKS success response write failed: " << ec.message() << "\n";
                    if (onError) onError();
                    return;
                }
                if (onSent) onSent();
            });
    }

} // namespace Vpn::Client