#include "VpnTransport.h"
#include "TLSHelper.h"
#include <iostream>

namespace Vpn::Client {

    VpnTransport::VpnTransport(boost::asio::io_context& ioContext,
        std::string serverIp,
        uint16_t serverPort,
        std::vector<uint8_t> serverPublicKey,
        std::string sniHost)
        : m_ioContext(ioContext),
        m_vpnSocket(ioContext),
        m_serverIp(std::move(serverIp)),
        m_serverPort(serverPort),
        m_serverPublicKey(std::move(serverPublicKey)),
        m_pingTimer(ioContext),
        m_reconnectTimer(ioContext),
        m_sniHost("dl.google.com")
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
        FrameHandler handler_to_destroy;
        {
            std::lock_guard<std::recursive_mutex> lock(m_handlersMutex);
            auto it = m_streamHandlers.find(streamId);
            if (it != m_streamHandlers.end()) {
                // Перемещаем лямбду во временную переменную, чтобы ее 
                // внутренний деструктор не вызвался внутри метода erase()
                handler_to_destroy = std::move(it->second);
                m_streamHandlers.erase(it);
            }
        }
        // Разрушение лямбды и вызов деструкторов сессий 
        // безопасно произойдут здесь, вне критической секции контейнера
    }

    void VpnTransport::Connect(std::function<void(bool success)> onConnected) {
        auto self = shared_from_this();

        boost::system::error_code socketEc;
        if (m_vpnSocket.is_open()) {
            m_vpnSocket.close(socketEc);
        }

        std::cout << "[VpnTransport] Resolving host " << m_serverIp << ":" << m_serverPort << "...\n";

        // Создаем резолвер и захватываем его в лямбду, чтобы он жил до конца запроса
        auto resolver = std::make_shared<boost::asio::ip::tcp::resolver>(m_ioContext);

        resolver->async_resolve(m_serverIp, std::to_string(m_serverPort),
            [this, self, onConnected, resolver](const boost::system::error_code& resolveEc, boost::asio::ip::tcp::resolver::results_type results) {
                if (resolveEc) {
                    std::cerr << "[VpnTransport ERROR] DNS Resolve failed: " << resolveEc.message() << "\n";
                    if (onConnected) onConnected(false);
                    return;
                }

                std::cout << "[VpnTransport] DNS resolved. Connecting TCP...\n";

                // async_connect сам попытается подключиться к первому доступному IP из results
                boost::asio::async_connect(m_vpnSocket, results,
                    [this, self, onConnected](boost::system::error_code connectEc, const boost::asio::ip::tcp::endpoint& endpoint) {
                        if (connectEc) {
                            std::cerr << "[VpnTransport ERROR] TCP Connect failed: " << connectEc.message()
                                << " (code: " << connectEc.value() << ")\n";
                            if (onConnected) onConnected(false);
                            return;
                        }

                        std::cout << "[VpnTransport] TCP connected to " << endpoint.address().to_string() << ". Sending ClientHello...\n";

                        m_vpnSocket.set_option(boost::asio::ip::tcp::no_delay(true));
                        auto myPubKey = m_cryptoEngine.GetLocalPublicKey();

                        auto tlsPacket = Protocol::TlsHelper::BuildClientHello(m_sniHost, myPubKey, m_serverPublicKey);
                        if (tlsPacket.empty()) {
                            std::cerr << "[VpnTransport ERROR] Failed to build ClientHello (check key validity)!\n";
                            if (onConnected) onConnected(false);
                            return;
                        }

                        auto fullTlsPacket = std::make_shared<std::vector<uint8_t>>(std::move(tlsPacket));

                        boost::asio::async_write(m_vpnSocket, boost::asio::buffer(*fullTlsPacket),
                            [this, self, onConnected, fullTlsPacket](boost::system::error_code writeEc, size_t bytesSent) {
                                if (writeEc) {
                                    std::cerr << "[VpnTransport ERROR] Write ClientHello failed: " << writeEc.message() << "\n";
                                    if (onConnected) onConnected(false);
                                    return;
                                }

                                std::cout << "[VpnTransport] ClientHello sent (" << bytesSent << " bytes). Waiting for ServerHello...\n";

                                auto headerBuf = std::make_shared<std::vector<uint8_t>>(5);

                                boost::asio::async_read(m_vpnSocket, boost::asio::buffer(*headerBuf),
                                    [this, self, onConnected, headerBuf](boost::system::error_code readEc, size_t) {
                                        if (readEc) {
                                            std::cerr << "[VpnTransport ERROR] Read ServerHello header failed: "
                                                << readEc.message() << " (Server rejected connection or closed socket)\n";
                                            if (onConnected) onConnected(false);
                                            return;
                                        }

                                        std::cout << "[VpnTransport] ServerHello header received successfully!\n";

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
                                                        DoReadHandshakeCertPayload(onConnected);
                                                    });
                                            });
                                    });
                            });
                    });
            });
    }

    void VpnTransport::DoReadHandshakeCertPayload(std::function<void(bool success)> onConnected) {
        auto self = shared_from_this();
        auto headerBuf = std::make_shared<std::array<uint8_t, 5>>();

        boost::asio::async_read(m_vpnSocket, boost::asio::buffer(headerBuf->data(), 5),
            [this, self, onConnected, headerBuf](boost::system::error_code ec, size_t) {
                if (ec) { if (onConnected) onConnected(false); return; }

                uint8_t contentType = (*headerBuf)[0];
                uint16_t payloadLen = (static_cast<uint16_t>((*headerBuf)[3]) << 8) | (*headerBuf)[4];

                if (contentType != 0x17 && contentType != 0x14) {
                    if (onConnected) onConnected(false);
                    return;
                }

                auto certPayloadBuf = std::make_shared<std::vector<uint8_t>>(payloadLen);
                boost::asio::async_read(m_vpnSocket, boost::asio::buffer(*certPayloadBuf),
                    [this, self, onConnected, certPayloadBuf, contentType](boost::system::error_code readEc, size_t) {
                        if (readEc) { if (onConnected) onConnected(false); return; }

                        if (contentType == 0x14) {
                            DoReadHandshakeCertPayload(onConnected);
                            return;
                        }

                        // Рукопожатие REALITY завершено, переходим к мультиплексированию
                        m_isConnected = true;
                        m_isReconnecting = false;
                        m_reconnectAttempt = 0;

                        std::cout << "[Transport] REALITY TLS 1.3 Tunnel established successfully! Mux Active.\n";

                        SendMuxFrame(Protocol::SYSTEM_STREAM_ID, Protocol::Command::Ping, {});
                        DoReadFrameHeader();
                        StartPingTimer();

                        if (onConnected) onConnected(true);
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

        // Статический генератор случайных чисел для потока
        static thread_local std::mt19937 rng(std::random_device{}());
        // Диапазон размеров куска (например, от 8000 до 14000 байт)
        std::uniform_int_distribution<size_t> chunkDist(8000, 14000);

        // Фрагментация на куски случайного размера
        do {
            // Генерируем случайный лимит для текущего фрагмента
            size_t currentChunkLimit = chunkDist(rng);

            size_t chunkSize = payload.empty() ? 0 : std::min(payload.size() - offset, currentChunkLimit);
            std::vector<uint8_t> chunk;
            if (chunkSize > 0) {
                chunk.assign(payload.begin() + offset, payload.begin() + offset + chunkSize);
            }

            auto plainMux = Protocol::StreamFrameHelper::PackMuxFrame(streamId, cmd, chunk);

            std::uniform_int_distribution<size_t> padDist(16, 128);
            auto padded = Protocol::PaddingHelper::AddPadding(plainMux, padDist(rng));
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