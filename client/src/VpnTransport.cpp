#include "VpnTransport.h"
#include "TlsHelper.h"
#include <iostream>

namespace Vpn::Client {

    VpnTransport::VpnTransport(boost::asio::io_context& ioContext,
        std::string serverIp,
        uint16_t serverPort,
        std::vector<uint8_t> serverPublicKey)
        : m_ioContext(ioContext),
        m_vpnSocket(ioContext),
        m_serverIp(std::move(serverIp)),
        m_serverPort(serverPort),
        m_serverPublicKey(std::move(serverPublicKey)),
        m_pingTimer(ioContext),
        m_reconnectTimer(ioContext)
    {
    }

    uint32_t VpnTransport::AllocateStreamId() {
        return m_nextStreamId++;
    }

    void VpnTransport::RegisterStream(uint32_t streamId, FrameHandler handler) {
        std::lock_guard<std::recursive_mutex> lock(m_handlersMutex);
        m_streamHandlers[streamId] = std::move(handler);
    }

    void VpnTransport::UnregisterStream(uint32_t streamId) {
        std::lock_guard<std::recursive_mutex> lock(m_handlersMutex);
        m_streamHandlers.erase(streamId);
    }

    void VpnTransport::Connect(std::function<void(bool success)> onConnected) {
        auto self = shared_from_this();

        boost::system::error_code socketEc;
        if (m_vpnSocket.is_open()) {
            m_vpnSocket.close(socketEc);
        }

        tcp::endpoint endpoint(boost::asio::ip::make_address(m_serverIp), m_serverPort);

        m_vpnSocket.async_connect(endpoint, [this, self, onConnected](boost::system::error_code ec) {
            if (ec) {
                if (onConnected) onConnected(false);
                return;
            }

            m_vpnSocket.set_option(boost::asio::ip::tcp::no_delay(true));
            auto myPubKey = m_cryptoEngine.GetLocalPublicKey();
            auto tlsPacket = Protocol::TlsHelper::BuildClientHello("dl.google.com", myPubKey, m_serverPublicKey);

            if (tlsPacket.size() <= 10) {
                if (onConnected) onConnected(false);
                return;
            }

            static thread_local std::mt19937 rng(std::random_device{}());
            std::uniform_int_distribution<size_t> dist(1, tlsPacket.size() - 10);
            size_t splitOffset = dist(rng); // Случайное разрезание ClientHello

            auto chunk1 = std::make_shared<std::vector<uint8_t>>(tlsPacket.begin(), tlsPacket.begin() + splitOffset);
            auto chunk2 = std::make_shared<std::vector<uint8_t>>(tlsPacket.begin() + splitOffset, tlsPacket.end());

            boost::asio::async_write(m_vpnSocket, boost::asio::buffer(*chunk1),
                [this, self, onConnected, chunk1, chunk2](boost::system::error_code writeEc1, size_t) {
                    if (writeEc1) { if (onConnected) onConnected(false); return; }

                    boost::asio::async_write(m_vpnSocket, boost::asio::buffer(*chunk2),
                        [this, self, onConnected, chunk2](boost::system::error_code writeEc2, size_t) {
                            if (writeEc2) { if (onConnected) onConnected(false); return; }

                            auto headerBuf = std::make_shared<std::vector<uint8_t>>(5);
                            boost::asio::async_read(m_vpnSocket, boost::asio::buffer(*headerBuf),
                                [this, self, onConnected, headerBuf](boost::system::error_code readEc, size_t) {
                                    if (readEc) { if (onConnected) onConnected(false); return; }

                                    uint16_t bodyLen = ((*headerBuf)[3] << 8) | (*headerBuf)[4];
                                    auto fullServerHello = std::make_shared<std::vector<uint8_t>>(5 + bodyLen);
                                    std::memcpy(fullServerHello->data(), headerBuf->data(), 5);

                                    boost::asio::async_read(m_vpnSocket, boost::asio::buffer(fullServerHello->data() + 5, bodyLen),
                                        [this, self, onConnected, fullServerHello](boost::system::error_code readBodyEc, size_t) {
                                            if (readBodyEc) { if (onConnected) onConnected(false); return; }

                                            std::vector<uint8_t> serverPubKey;
                                            if (!Protocol::TlsHelper::ParseServerHello(*fullServerHello, serverPubKey)) {
                                                if (onConnected) onConnected(false);
                                                return;
                                            }

                                            m_sessionKey = m_cryptoEngine.DeriveSharedSecret(serverPubKey);
                                            if (m_sessionKey.empty()) {
                                                if (onConnected) onConnected(false);
                                                return;
                                            }

                                            auto ccsBuf = std::make_shared<std::vector<uint8_t>>(
                                                std::initializer_list<uint8_t>{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}
                                            );

                                            boost::asio::async_write(m_vpnSocket, boost::asio::buffer(*ccsBuf),
                                                [this, self, onConnected, ccsBuf](boost::system::error_code ccsEc, size_t) {
                                                    if (ccsEc) { if (onConnected) onConnected(false); return; }

                                                    m_isConnected = true;
                                                    m_isReconnecting = false;
                                                    m_reconnectAttempt = 0;

                                                    std::cout << "[Transport] Main Mux TLS Tunnel established successfully!\n";

                                                    SendMuxFrame(Protocol::SYSTEM_STREAM_ID, Protocol::Command::Ping, {});

                                                    DoReadFrameHeader();
                                                    StartPingTimer();

                                                    if (onConnected) onConnected(true);
                                                });
                                        });

                                });
                        });
                });
            });
    }

    void VpnTransport::DoReadFrameHeader() {
        auto self = shared_from_this();
        auto headerBuf = std::make_shared<std::array<uint8_t, 5>>();

        boost::asio::async_read(m_vpnSocket, boost::asio::buffer(headerBuf->data(), 5),
            [this, self, headerBuf](boost::system::error_code ec, size_t) {
                if (ec) { Close(); return; }

                uint16_t payloadLen = (static_cast<uint16_t>((*headerBuf)[3]) << 8) | (*headerBuf)[4];

                if ((*headerBuf)[0] != 0x17) {
                    if (payloadLen == 0 || payloadLen > Protocol::MAX_FRAME_SIZE) {
                        Close();
                        return;
                    }

                    auto skipBuf = std::make_shared<std::vector<uint8_t>>(payloadLen);
                    boost::asio::async_read(m_vpnSocket, boost::asio::buffer(*skipBuf),
                        [this, self, skipBuf](boost::system::error_code skipEc, size_t) {
                            if (skipEc) { Close(); return; }
                            DoReadFrameHeader();
                        });
                    return;
                }

                if (payloadLen == 0 || payloadLen > Protocol::MAX_FRAME_SIZE) {
                    Close();
                    return;
                }

                DoReadFramePayload(payloadLen);
            });
    }

    void VpnTransport::DoReadFramePayload(uint16_t payloadLen) {
        auto self = shared_from_this();
        m_payloadBuffer.resize(payloadLen);

        boost::asio::async_read(m_vpnSocket, boost::asio::buffer(m_payloadBuffer.data(), payloadLen),
            [this, self](boost::system::error_code ec, size_t) {
                if (ec) { Close(); return; }
                ProcessMuxFrame(m_payloadBuffer);
            });
    }

    void VpnTransport::ProcessMuxFrame(const std::vector<uint8_t>& encryptedData) {
        if (encryptedData.size() <= Protocol::IV_SIZE + Protocol::TAG_SIZE) {
            Close(); return;
        }

        std::vector<uint8_t> iv(encryptedData.begin(), encryptedData.begin() + Protocol::IV_SIZE);
        std::vector<uint8_t> authTag(encryptedData.end() - Protocol::TAG_SIZE, encryptedData.end());
        std::vector<uint8_t> cipherText(encryptedData.begin() + Protocol::IV_SIZE, encryptedData.end() - Protocol::TAG_SIZE);

        std::vector<uint8_t> decryptedText, plainText;
        if (!m_cryptoEngine.DecryptPayload(cipherText, m_sessionKey, iv, authTag, decryptedText) ||
            !Protocol::PaddingHelper::RemovePadding(decryptedText, plainText)) {
            Close(); return;
        }

        Protocol::MuxFrame frame;
        if (!Protocol::StreamFrameHelper::UnpackMuxFrame(plainText, frame)) {
            Close(); return;
        }

        if (frame.streamId == Protocol::SYSTEM_STREAM_ID) {
            // Системный Pong или Ping
        }
        else {
            FrameHandler handler;
            {
                std::lock_guard<std::recursive_mutex> lock(m_handlersMutex);
                auto it = m_streamHandlers.find(frame.streamId);
                if (it != m_streamHandlers.end()) {
                    handler = it->second;
                }
            }
            if (handler) {
                handler(frame);
            }
        }

        DoReadFrameHeader();
    }

    void VpnTransport::SendMuxFrame(uint32_t streamId, Protocol::Command cmd, const std::vector<uint8_t>& payload) {
        if (!m_isConnected) return;

        size_t offset = 0;
        const size_t MAX_CHUNK_SIZE = 15000;

        // Фрагментация на куски по 15000 байт 
        do {
            size_t chunkSize = payload.empty() ? 0 : std::min(payload.size() - offset, MAX_CHUNK_SIZE);
            std::vector<uint8_t> chunk;
            if (chunkSize > 0) {
                chunk.assign(payload.begin() + offset, payload.begin() + offset + chunkSize);
            }

            auto plainMux = Protocol::StreamFrameHelper::PackMuxFrame(streamId, cmd, chunk);

            static thread_local std::mt19937 rng(std::random_device{}());
            std::uniform_int_distribution<size_t> dist(16, 128);
            auto padded = Protocol::PaddingHelper::AddPadding(plainMux, dist(rng));
            auto iv = CryptoEngine::GenerateRandomBytes(Protocol::IV_SIZE);

            std::vector<uint8_t> cipherText, authTag;
            if (!m_cryptoEngine.EncryptPayload(padded, m_sessionKey, iv, cipherText, authTag)) {
                return;
            }

            auto tlsRecord = std::make_shared<std::vector<uint8_t>>();
            tlsRecord->push_back(0x17);
            tlsRecord->push_back(0x03); tlsRecord->push_back(0x03);
            uint16_t len = static_cast<uint16_t>(iv.size() + cipherText.size() + authTag.size());
            tlsRecord->push_back(len >> 8);
            tlsRecord->push_back(len & 0xFF);
            tlsRecord->insert(tlsRecord->end(), iv.begin(), iv.end());
            tlsRecord->insert(tlsRecord->end(), cipherText.begin(), cipherText.end());
            tlsRecord->insert(tlsRecord->end(), authTag.begin(), authTag.end());

            boost::asio::post(m_ioContext, [this, self = shared_from_this(), tlsRecord]() {
                m_writeQueue.push_back(tlsRecord);
                if (!m_isWriting) {
                    DoWriteQueue();
                }
                });

            offset += chunkSize;
        } while (offset < payload.size());
    }

    void VpnTransport::DoWriteQueue() {
        if (m_writeQueue.empty()) {
            m_isWriting = false;
            return;
        }

        m_isWriting = true;
        auto self = shared_from_this();
        auto bufferPtr = m_writeQueue.front(); // Удержание памяти

        boost::asio::async_write(m_vpnSocket, boost::asio::buffer(*bufferPtr),
            [this, self, bufferPtr](boost::system::error_code ec, size_t) {
                if (ec) { Close(); return; }
                m_writeQueue.pop_front();
                DoWriteQueue();
            });
    }

    void VpnTransport::StartPingTimer() {
        auto self = shared_from_this();

        static thread_local std::mt19937 rng(std::random_device{}());
        std::uniform_int_distribution<int> dist(10, 35);
        int jitterSec = dist(rng);

        m_pingTimer.expires_after(std::chrono::seconds(jitterSec));
        m_pingTimer.async_wait([this, self](boost::system::error_code ec) {
            if (!ec && m_isConnected) {
                SendMuxFrame(Protocol::SYSTEM_STREAM_ID, Protocol::Command::Ping, {});
                StartPingTimer();
            }
            });
    }

    void VpnTransport::ScheduleReconnect() {
        if (!m_shouldAutoReconnect || m_isReconnecting) return;

        m_isReconnecting = true;
        m_reconnectAttempt++;

        int delaySec = std::min(1 << m_reconnectAttempt, 30);
        std::cout << "[Transport] Tunnel lost. Reconnecting in " << delaySec
            << "s (Attempt #" << m_reconnectAttempt << ")...\n";

        m_reconnectTimer.expires_after(std::chrono::seconds(delaySec));
        auto self = shared_from_this();

        m_reconnectTimer.async_wait([this, self](boost::system::error_code ec) {
            if (ec) return;

            Connect([this, self](bool success) {
                if (!success) {
                    m_isReconnecting = false;
                    ScheduleReconnect();
                }
                });
            });
    }

    void VpnTransport::Close() {
        bool wasConnected = m_isConnected;
        m_isConnected = false;

        m_pingTimer.cancel();

        boost::system::error_code ec;
        if (m_vpnSocket.is_open()) {
            m_vpnSocket.close(ec);
        }

        std::unordered_map<uint32_t, FrameHandler> handlersToDestroy;
        {
            std::lock_guard<std::recursive_mutex> lock(m_handlersMutex);
            handlersToDestroy = std::move(m_streamHandlers);
        }

        m_writeQueue.clear();
        m_isWriting = false;

        if (wasConnected && m_shouldAutoReconnect) {
            ScheduleReconnect();
        }
    }

} // namespace Vpn::Client