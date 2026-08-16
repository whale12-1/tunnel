#include "LocalProxySession.h"
#include "TlsHelper.h"
#include <iostream>

namespace Vpn::Client {

    LocalProxySession::LocalProxySession(tcp::socket appSocket, std::shared_ptr<VpnTransport> transport)
        : m_appSocket(std::move(appSocket)),
        m_transport(std::move(transport)),
        m_myStreamId(m_transport->AllocateStreamId()) {
    }

    LocalProxySession::~LocalProxySession() {
        Close();
    }

    void LocalProxySession::Start() {
        auto self = shared_from_this();
        m_transport->RegisterStream(m_myStreamId, [this, self](const Protocol::MuxFrame& frame) {
            OnMuxFrameReceived(frame);
            });

        DoReadSocksHandshake();
    }

    void LocalProxySession::DoReadSocksHandshake() {
        auto self = shared_from_this();

        boost::asio::async_read(
            m_appSocket,
            boost::asio::buffer(m_buffer, 2),
            [this, self](boost::system::error_code ec, size_t) {
                if (ec || m_buffer[0] != 0x05) {
                    std::cerr << "[Client Proxy Error] SOCKS handshake failed: " << ec.message() << "\n";
                    Close();
                    return;
                }

                uint8_t nmethods = m_buffer[1];

                boost::asio::async_read(
                    m_appSocket,
                    boost::asio::buffer(m_buffer, nmethods),
                    [this, self](boost::system::error_code readEc, size_t) {
                        if (readEc) {
                            std::cerr << "[Client Proxy Error] SOCKS methods read failed: " << readEc.message() << "\n";
                            Close();
                            return;
                        }

                        static const uint8_t response[] = { 0x05, 0x00 };
                        boost::asio::async_write(m_appSocket, boost::asio::buffer(response, 2),
                            [this, self](boost::system::error_code writeEc, size_t) {
                                if (writeEc) {
                                    std::cerr << "[Client Proxy Error] SOCKS response write failed: " << writeEc.message() << "\n";
                                    Close();
                                    return;
                                }
                                DoReadSocksRequestHeader();
                            });
                    }
                );
            }
        );
    }

    void LocalProxySession::DoReadSocksRequestHeader() {
        auto self = shared_from_this();
        boost::asio::async_read(m_appSocket, boost::asio::buffer(m_buffer, 4),
            [this, self](boost::system::error_code ec, size_t) {
                if (ec || m_buffer[0] != 0x05 || m_buffer[1] != 0x01) {
                    std::cerr << "[Client Proxy Error] SOCKS request header failed: " << ec.message() << "\n";
                    Close();
                    return;
                }
                DoReadSocksAddress(m_buffer[3]);
            });
    }

    void LocalProxySession::DoReadSocksAddress(uint8_t socksAddressType) {
        auto self = shared_from_this();

        if (socksAddressType == 0x01) { // IPv4
            boost::asio::async_read(m_appSocket, boost::asio::buffer(m_buffer, 6),
                [this, self](boost::system::error_code ec, size_t) {
                    if (ec) { std::cerr << "[Client Proxy Error] IPv4 address read failed: " << ec.message() << "\n"; Close(); return; }
                    Protocol::TargetAddress target{ Protocol::AddressType::IPv4 };
                    boost::asio::ip::address_v4 ip(
                        (static_cast<uint8_t>(m_buffer[0]) << 24) |
                        (static_cast<uint8_t>(m_buffer[1]) << 16) |
                        (static_cast<uint8_t>(m_buffer[2]) << 8) |
                        static_cast<uint8_t>(m_buffer[3]));
                    target.address = ip.to_string();
                    target.port = (static_cast<uint8_t>(m_buffer[4]) << 8) | static_cast<uint8_t>(m_buffer[5]);
                    OpenVpnStream(target);
                });
        }
        else if (socksAddressType == 0x03) { // Domain
            boost::asio::async_read(m_appSocket, boost::asio::buffer(m_buffer, 1),
                [this, self](boost::system::error_code ec, size_t) {
                    if (ec) { std::cerr << "[Client Proxy Error] Domain length read failed: " << ec.message() << "\n"; Close(); return; }
                    uint8_t domainLen = static_cast<uint8_t>(m_buffer[0]);
                    auto domainBuf = std::make_shared<std::vector<uint8_t>>(domainLen + 2);

                    boost::asio::async_read(m_appSocket, boost::asio::buffer(*domainBuf),
                        [this, self, domainLen, domainBuf](boost::system::error_code readEc, size_t) {
                            if (readEc) { std::cerr << "[Client Proxy Error] Domain name read failed: " << readEc.message() << "\n"; Close(); return; }
                            Protocol::TargetAddress target{ Protocol::AddressType::Domain };
                            target.address = std::string(reinterpret_cast<const char*>(domainBuf->data()), domainLen);
                            target.port = (static_cast<uint16_t>((*domainBuf)[domainLen]) << 8) |
                                static_cast<uint16_t>((*domainBuf)[domainLen + 1]);

                            m_sniHost = target.address;
                            OpenVpnStream(target);
                        });
                });
        }
        else {
            std::cerr << "[Client Proxy Error] Unsupported SOCKS address type: " << (int)socksAddressType << "\n";
            Close();
        }
    }

    void LocalProxySession::OpenVpnStream(const Protocol::TargetAddress& target) {
        std::cout << "[Client Proxy] Opening VPN stream #" << m_myStreamId << " for " << target.address << ":" << target.port << "\n";
        auto targetPayload = Protocol::StreamFrameHelper::SerializeTargetAddress(target);
        m_transport->SendMuxFrame(m_myStreamId, Protocol::Command::StreamOpen, targetPayload);
    }

    void LocalProxySession::OnMuxFrameReceived(const Protocol::MuxFrame& frame) {
        if (frame.command == Protocol::Command::StreamOpen) {
            std::cout << "[Client Proxy] Stream #" << m_myStreamId << " opened successfully by server.\n";
            SendSocksSuccessResponse();
        }
        else if (frame.command == Protocol::Command::StreamData) {
            DoWriteToApp(frame.payload.data(), frame.payload.size());
        }
        // Обработка Half-Close от сервера
        else if (frame.command == Protocol::Command::StreamHalfClose) {
            std::cout << "[Client Proxy] Half-close received from server for stream #" << m_myStreamId << "\n";
            boost::system::error_code ec;
            m_appSocket.shutdown(tcp::socket::shutdown_send, ec);
        }
        else if (frame.command == Protocol::Command::StreamClose) {
            std::cout << "[Client Proxy] Stream #" << m_myStreamId << " closed by server.\n";
            Close();
        }
    }

    void LocalProxySession::SendSocksSuccessResponse() {
        auto self = shared_from_this();
        static const uint8_t successResponse[10] = { 0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0 };

        boost::asio::async_write(m_appSocket, boost::asio::buffer(successResponse, 10),
            [this, self](boost::system::error_code ec, size_t) {
                if (ec) {
                    std::cerr << "[Client Proxy Error] SOCKS success response write failed: " << ec.message() << "\n";
                    Close();
                    return;
                }
                m_isTunneling = true;
                std::cout << "[Client Proxy] SOCKS tunneling active for stream #" << m_myStreamId << "\n";
                DoReadFromApp();
            });
    }

    void LocalProxySession::DoReadFromApp() {
        auto self = shared_from_this();

        if (m_isHalfClosed) return;

        m_appSocket.async_read_some(
            boost::asio::buffer(m_appBuf),
            [this, self](boost::system::error_code ec, size_t length) {

                if (ec) {
                    if (ec == boost::asio::error::eof ||
                        ec.value() == 1236 || ec.value() == 10053 || ec.value() == 995) {

                        std::cout << "[Client Proxy] App finished sending data (Stream #"
                            << m_myStreamId << "). Sending HalfClose.\n";

                        m_isHalfClosed = true;
                        m_transport->SendMuxFrame(m_myStreamId, Protocol::Command::StreamHalfClose, {});

                        boost::system::error_code shutdownEc;
                        m_appSocket.shutdown(tcp::socket::shutdown_send, shutdownEc);
                        return;
                    }

                    std::cerr << "[Client Proxy Error] Fatal read from app: " << ec.message() << "\n";
                    Close();
                    return;
                }

                if (length > 0) {
                    std::vector<uint8_t> data(m_appBuf.begin(), m_appBuf.begin() + length);
                    m_transport->SendMuxFrame(m_myStreamId, Protocol::Command::StreamData, data);
                    DoReadFromApp();
                }
            }
        );
    }

    void LocalProxySession::DoWriteToApp(const uint8_t* data, size_t length) {
        auto self = shared_from_this();
        m_writeQueue.push_back(std::make_shared<std::vector<uint8_t>>(data, data + length));

        if (!m_isWriting) {
            DoWriteToAppQueue();
        }
    }

    void LocalProxySession::DoWriteToAppQueue() {
        if (m_writeQueue.empty()) {
            m_isWriting = false;
            return;
        }

        m_isWriting = true;
        auto self = shared_from_this();
        auto bufferPtr = m_writeQueue.front(); // Удержание памяти

        boost::asio::async_write(m_appSocket, boost::asio::buffer(*bufferPtr),
            [this, self, bufferPtr](boost::system::error_code ec, size_t bytesTransferred) {
                if (ec) {
                    std::cerr << "[Client Proxy Error] Write to app (curl) failed on stream #" << m_myStreamId
                        << ": " << ec.message() << "\n";
                    Close();
                    return;
                }

                m_writeQueue.pop_front();
                DoWriteToAppQueue();
            });
    }

    void LocalProxySession::Close() {
        if (m_myStreamId != 0) {
            std::cout << "[Client Proxy] Closing session for stream #" << m_myStreamId << "\n";
            m_transport->SendMuxFrame(m_myStreamId, Protocol::Command::StreamClose, {});
            m_transport->UnregisterStream(m_myStreamId);
            m_myStreamId = 0;
        }

        m_writeQueue.clear();
        m_isWriting = false;

        boost::system::error_code ec;
        if (m_appSocket.is_open()) m_appSocket.close(ec);
    }

} // namespace Vpn::Client