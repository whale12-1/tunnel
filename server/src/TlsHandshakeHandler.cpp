#include "TlsHandshakeHandler.h"
#include "TLSHelper.h"
#include <iostream>
#include <random>

namespace Vpn::Server {

    TlsHandshakeHandler::TlsHandshakeHandler(std::shared_ptr<CryptoEngine> cryptoEngine, boost::asio::any_io_executor executor)
        : m_socket(executor),
        m_cryptoEngine(std::move(cryptoEngine)) {
    }

    void TlsHandshakeHandler::Start(tcp::socket socket, SuccessCallback onSuccess, FallbackCallback onFallback) {
        m_socket = std::move(socket);
        m_onSuccess = std::move(onSuccess);
        m_onFallback = std::move(onFallback);
        DoReadHandshake();
    }

    void TlsHandshakeHandler::DoReadHandshake() {
        auto self = shared_from_this();
        m_payloadBuffer.resize(5);

        boost::asio::async_read(m_socket, boost::asio::buffer(m_payloadBuffer.data(), 5),
            [this, self](boost::system::error_code ec, size_t) {
                if (ec || m_payloadBuffer[0] != 0x16) {
                    std::cerr << "[Server Error] Handshake header read failed or not Handshake type\n";
                    boost::system::error_code closeEc; m_socket.close(closeEc);
                    return;
                }

                uint16_t bodyLen = (static_cast<uint16_t>(m_payloadBuffer[3]) << 8) | m_payloadBuffer[4];
                if (bodyLen < 71 || bodyLen > Protocol::MAX_FRAME_SIZE) {
                    std::cerr << "[Server Error] Invalid handshake bodyLen: " << bodyLen << "\n";
                    boost::system::error_code closeEc; m_socket.close(closeEc);
                    return;
                }

                DoReadTlsBody(bodyLen);
            }
        );
    }

    void TlsHandshakeHandler::DoReadTlsBody(uint16_t bodyLen) {
        auto self = shared_from_this();
        auto fullTlsPacket = std::make_shared<std::vector<uint8_t>>();
        fullTlsPacket->insert(fullTlsPacket->end(), m_payloadBuffer.begin(), m_payloadBuffer.begin() + 5);
        fullTlsPacket->resize(5 + bodyLen);

        boost::asio::async_read(m_socket, boost::asio::buffer(fullTlsPacket->data() + 5, bodyLen),
            [this, self, fullTlsPacket](boost::system::error_code ec, size_t) {
                if (ec) {
                    std::cerr << "[Server Error] Handshake body read failed\n";
                    boost::system::error_code closeEc; m_socket.close(closeEc);
                    return;
                }

                std::vector<uint8_t> clientPubKey;
                std::string sniHost;
                auto localPubKey = m_cryptoEngine->GetLocalPublicKey();

                if (!Protocol::TlsHelper::VerifyAndParseClientHello(*fullTlsPacket, localPubKey, clientPubKey, sniHost)) {
                    std::cout << "[Server] Active probe or invalid HMAC. Fallback...\n";
                    FinishWithFallback(fullTlsPacket);
                    return;
                }

                auto sessionKey = m_cryptoEngine->DeriveSharedSecret(clientPubKey);
                if (sessionKey.empty()) {
                    std::cerr << "[Server Error] Failed to derive shared secret.\n";
                    FinishWithFallback(fullTlsPacket);
                    return;
                }

                std::cout << "[Server] Valid TLS ClientHello received (SNI: " << sniHost << "). Handshake success!\n";

                std::vector<uint8_t> clientSessionId(fullTlsPacket->begin() + 44, fullTlsPacket->begin() + 76);
                auto serverHelloPacket = Protocol::TlsHelper::BuildServerHello(localPubKey, clientSessionId);
                auto serverHelloBuf = std::make_shared<std::vector<uint8_t>>(std::move(serverHelloPacket));

                boost::asio::async_write(m_socket, boost::asio::buffer(*serverHelloBuf),
                    [this, self, serverHelloBuf, sessionKey = std::move(sessionKey)](boost::system::error_code writeEc, size_t) mutable {
                        if (writeEc) { boost::system::error_code closeEc; m_socket.close(closeEc); return; }

                        static thread_local std::mt19937 rng(std::random_device{}());
                        std::uniform_int_distribution<size_t> dist(2600, 3400);

                        auto fakeCertRecord = Protocol::TlsHelper::BuildFakeTls13HandshakePayload(dist(rng));
                        auto fakeCertBuf = std::make_shared<std::vector<uint8_t>>(std::move(fakeCertRecord));

                        boost::asio::async_write(m_socket, boost::asio::buffer(*fakeCertBuf),
                            [this, self, fakeCertBuf, sessionKey = std::move(sessionKey)](boost::system::error_code certWriteEc, size_t) mutable {
                                if (certWriteEc) { boost::system::error_code closeEc; m_socket.close(closeEc); return; }

                                std::cout << "[Server] REALITY TLS 1.3 Handshake completed successfully! Mux Active.\n";
                                if (m_onSuccess) m_onSuccess(std::move(m_socket), std::move(sessionKey));
                            }
                        );
                    }
                );
            }
        );
    }

    void TlsHandshakeHandler::FinishWithFallback(std::shared_ptr<std::vector<uint8_t>> initialPacket) {
        if (m_onFallback) {
            m_onFallback(std::move(m_socket), initialPacket);
        }
    }

} // namespace Vpn::Server